import base64
from datetime import datetime, timedelta
import hashlib
import hmac
import os
from uuid import uuid4
from cgi import escape
import requests

from jinja2 import Template, FileSystemLoader
from jinja2.environment import Environment
try:
    from urllib.parse import urljoin
except ImportError:
    from urlparse import urljoin


def render_to_string(template_name, context=None):
    if context is None:
        context = {}

    env = Environment()
    env.loader = FileSystemLoader('.')
    tmpl = env.get_template(template_name)
    return tmpl.render(context)


def fix_suds():
    # suds.sax.parser has a broken reference to
    # suds.metrics somehow?  dunno if just my install
    # or due to their import *s or what.
    import suds
    try:
        suds.metrics
    except AttributeError:
        import suds.metrics as suds_metrics
        suds.metrics = suds_metrics


class DynamicsCrmSettingsError(Exception):
    pass


class CrmAuthenticationError(Exception):
    pass


class DynamicsCrmSettings(object):
    debug_requests = False

    soap_api_path = 'XRMServices/2011/Organization.svc'

    def __init__(self, **kwargs):
        self.is_crm_online = kwargs.get('is_crm_online', False)
        self.password = kwargs.get('password', '')
        self.url = kwargs.get('url', '')
        self.username = kwargs.get('username', '')

        self.now = datetime.now()
        self.log_tag = '%s.%d-%x' % (self.now.strftime('%y%m%d.%H%M%S'),
                                     os.getpid(), id(self))

    @property
    def login_url(self):
        if self.is_crm_online:
            return "https://login.microsoftonline.com/RST2.srf"
        else:
            return urljoin(self.get_adfs(), 'trust/13/usernamemixed')

    @property
    def urn_address(self):
        if self.is_crm_online:
            return self.urn_address_online()
        else:
            return urljoin(self.url, self.soap_api_path)

    def urn_address_online(self):
        """
        :return: the URN Address based on the Online region.
        """
        if "CRM2.DYNAMICS.COM" in self.url.upper():
            return "crmsam:dynamics.com"
        elif "CRM4.DYNAMICS.COM" in self.url.upper():
            return "crmemea:dynamics.com"
        elif "CRM5.DYNAMICS.COM" in self.url.upper():
            return "crmapac:dynamics.com"
        elif "CRM6.DYNAMICS.COM" in self.url.upper():
            return "crmoce:dynamics.com"
        elif "CRM7.DYNAMICS.COM" in self.url.upper():
            return "crmjpn:dynamics.com"
        elif "CRM8.DYNAMICS.COM" in self.url.upper():
            return "crmgcc:dynamics.com"
        else:
            return "crmna:dynamics.com"

    def get_headers(self, content):
        return {
            'Content-Type': 'application/soap+xml; charset=UTF-8',
            'Content-Length': len(content),
        }

    def generate_auth_request_body_online(self):
        now = datetime.now().isoformat()
        expiration = (datetime.now() + timedelta(minutes=20)).isoformat()
        context = {
            'username': self.username,
            'password': self.password,
            'urn_address': self.urn_address,
            'now': now,
            'expiration': expiration,
            'random_uuid': uuid4,
        }
        return render_to_string('dynamics_crm/auth_request_online.xml', context)

    def generate_auth_request_body_on_premise(self):
        expiration = (self.now + timedelta(minutes=60)).isoformat()
        context = {
            'username': self.username,
            'login_url': self.login_url,
            'password': self.password,
            'urn_address': self.urn_address,
            'now': self.now.isoformat(),
            'expiration': expiration,
            'random_uuid': uuid4,
        }
        return render_to_string('dynamics_crm/auth_request_on_premise.xml', context)

    def get_authentication_xml_block(self, message_type):
        if self.is_crm_online:
            request_body = self.generate_auth_request_body_online()
        else:
            request_body = self.generate_auth_request_body_on_premise()
        headers = self.get_headers(request_body)
        self._write_debug_file('login_request', request_body)
        resp = requests.post(self.login_url, request_body, headers=headers, verify=False)
        self._write_debug_file('login_response', resp.content)
        if resp.status_code != 200:
            raise CrmAuthenticationError(resp.content)
        return self.generate_auth_header(resp.content, message_type)

    def generate_auth_header(self, resp_content, message_type):
        if self.is_crm_online:
            return self.generate_auth_header_online(resp_content, message_type)
        else:
            return self.generate_auth_header_on_premise(resp_content, message_type)

    def generate_auth_header_on_premise(self, resp_content, message_type):
        tokens = self.extract_auth_tokens_on_premise(resp_content)
        context = {
            'url': self.url,
            'random_uuid': uuid4,
            'message_type': message_type
        }
        context.update(tokens)
        return render_to_string('dynamics_crm/auth_header_on_premise.xml', context)

    def generate_auth_header_online(self, resp_content, message_type):
        tokens = self.extract_auth_tokens_online(resp_content)
        context = {
            'url': self.url,
            'random_uuid': uuid4,
            'message_type': message_type
        }
        context.update(tokens)
        return render_to_string('dynamics_crm/auth_header_online.xml', context)

    def extract_auth_tokens_online(self, resp_content):
        fix_suds()
        from suds.sax.parser import Parser
        p = Parser()
        doc = p.parse(string=resp_content)

        rst_encrypted_data = doc.childAtPath('Envelope/Body/RequestSecurityTokenResponse/RequestedSecurityToken/EncryptedData')

        token_ciphertext = rst_encrypted_data.childAtPath('CipherData/CipherValue').text

        encrypted_key = rst_encrypted_data.childAtPath('KeyInfo/EncryptedKey')
        key_ident = encrypted_key.childAtPath('KeyInfo/SecurityTokenReference/KeyIdentifier').text
        key_ciphertext = encrypted_key.childAtPath('CipherData/CipherValue').text

        # raise CrmAuthenticationError("KeyIdentifier or CipherValue not found
        # in", resp_content)
        context = {
            'key_ciphertext': key_ciphertext,
            'token_ciphertext': token_ciphertext,
            'key_ident': key_ident,
        }
        return context

    def extract_auth_tokens_on_premise(self, resp_content):
        fix_suds()
        from suds.sax.parser import Parser
        p = Parser()
        doc = p.parse(string=resp_content)

        created = (self.now - timedelta(minutes=1)).isoformat()
        expires = (self.now + timedelta(minutes=60)).isoformat()
        rst_resp = doc.childAtPath('Envelope/Body/RequestSecurityTokenResponseCollection/RequestSecurityTokenResponse')
        key_ident = rst_resp.childAtPath('RequestedAttachedReference/SecurityTokenReference/KeyIdentifier').text
        binary_secret = rst_resp.childAtPath('RequestedProofToken/BinarySecret').text
        signature, signature_digest = self.generate_hmac_signature(binary_secret, created, expires)

        enc_data = rst_resp.childAtPath('RequestedSecurityToken/EncryptedData')
        key_ciphertext = enc_data.childAtPath('KeyInfo/EncryptedKey/CipherData/CipherValue').text
        token_ciphertext = enc_data.childAtPath('CipherData/CipherValue').text
        x509_info = enc_data.childAtPath('KeyInfo/EncryptedKey/KeyInfo/SecurityTokenReference/X509Data/X509IssuerSerial')
        issuer_name_x509 = x509_info.childAtPath('X509IssuerName').text
        serial_number_x509 = x509_info.childAtPath('X509SerialNumber').text

        context = {
            'key_ciphertext': key_ciphertext,
            'token_ciphertext': token_ciphertext,
            'key_ident': key_ident,
            'created': created,
            'expires': expires,
            'issuer_name_x509': issuer_name_x509,
            'serial_number_x509': serial_number_x509,
            'signature_digest': signature_digest,
            'signature': signature,
        }
        return context

    def generate_hmac_signature(self, binary_secret, created, expires):

        timestamp = render_to_string('dynamics_crm/timestamp.xml',
                                     {'created': created, 'expires': expires})

        timestamp_hasher = hashlib.sha1()
        timestamp_hasher.update(timestamp.encode('utf8'))
        timestamp_digest = base64.b64encode(timestamp_hasher.digest()).decode('ascii')
        signed_info = render_to_string('dynamics_crm/hmac.xml', {'digest': timestamp_digest})
        hashed = base64.b64encode(hmac.new(base64.b64decode(binary_secret), signed_info.encode('utf8'), hashlib.sha1).digest()).decode('ascii')
        return hashed, timestamp_digest

    def get_adfs(self):
        if not self.url:
            raise DynamicsCrmSettingsError('url needed')
        url = urljoin(self.url, self.soap_api_path) + '?wsdl=wsdl0'
        resp = requests.get(url, verify=False)
        self._write_debug_file('wsdl_response', resp.content)
        if resp.status_code != 200:
            raise CrmAuthenticationError('Could not get ADFS: ' + resp.content)
        return self.extract_adfs_url(resp.content)

    def extract_adfs_url(self, resp_content):
        fix_suds()
        from suds.sax.parser import Parser
        p = Parser()
        doc = p.parse(string=resp_content)

        all_policies = doc.childAtPath('definitions/Policy/ExactlyOne/All')
        url = all_policies.childAtPath('AuthenticationPolicy/SecureTokenService/Identifier').text
        return url.replace('http:', 'https:')

    def make_whoami_request(self):
        whoami = render_to_string('dynamics_crm/whoami.xml')

        resp = self.make_soap_request(whoami, "Execute")
        if resp.status_code == 200:
            return self.get_whoami(resp.content)
        else:
            raise DynamicsCrmSettingsError('Dynamcs CRM Error ({}): {}'.format(resp.status_code, resp.content))

    def make_soap_request(self, request_body, message_type):
        url = urljoin(self.url, self.soap_api_path)
        auth_header = self.get_authentication_xml_block(message_type)
        context = {
            'header': auth_header,
            'request_body': request_body,
        }
        
        req_body = render_to_string('dynamics_crm/soap_request.xml', context)
        headers = self.get_headers(req_body)
        self._write_debug_file('soap_request', req_body)
        resp = requests.post(url, req_body, headers=headers, verify=False)
        self._write_debug_file('soap_response', resp.content)
        return resp

    def _write_debug_file(self, name, content):
        if not self.debug_requests:
            return

        name = name + self.log_tag + '.xml'
        with open(name, 'w') as output:
            output.write(content)
        return name

    def get_users(self):
        fetch = render_to_string('dynamics_crm/fetch_users.xml')
        escaped_fetch = escape(fetch)
        request = render_to_string('dynamics_crm/retrieve_multiple.xml',
                                   {'escaped_fetch': escaped_fetch})
        resp = self.make_soap_request(request, 'RetrieveMultiple')
        if resp.status_code == 200:
            return self.extract_users(resp.content)
        else:
            raise DynamicsCrmSettingsError('Dynamcs CRM Error ({}): {}'.format(resp.status_code, resp.content))

    def get_whoami(self, resp_content):
        fix_suds()
        from suds.sax.parser import Parser
        p = Parser()
        doc = p.parse(string=resp_content)

        id = ''
        results = doc.childAtPath('Envelope/Body/ExecuteResponse/ExecuteResult/Results')
        for result in results.children:
            if result.childAtPath('key').text == 'UserId':
                id = result.childAtPath('value').text

        return id

    def extract_users(self, resp_content):
        fix_suds()
        from suds.sax.parser import Parser
        p = Parser()
        doc = p.parse(string=resp_content)

        users = []
        user_elements = doc.childAtPath('Envelope/Body/RetrieveMultipleResponse/RetrieveMultipleResult/Entities')
        for user in user_elements.children:
            user_info = {}
            attributes = user.childrenAtPath('Attributes/KeyValuePairOfstringanyType')
            for attr in attributes:
                if attr.childAtPath('key').text == 'systemuserid':
                    user_info['id'] = attr.childAtPath('value').text
                elif attr.childAtPath('key').text == 'internalemailaddress':
                    user_info['internalemailaddress'] = attr.childAtPath('value').text
                elif attr.childAtPath('key').text == 'fullname':
                    fullname = attr.childAtPath('value').text
                    user_info['last_name'] = ' '.join(fullname.split()[-1:])
                    user_info['first_name'] = ' '.join(fullname.split()[:-1])
            users.append(user_info)
        return users

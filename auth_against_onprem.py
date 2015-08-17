#!/usr/bin/env python
from dynamics import DynamicsCrmSettings


url = raw_input('Url: ')
username = raw_input('Username: ')
password = raw_input('Password: ')

dyn = DynamicsCrmSettings(
    url=url,
    username=username,
    password=password,
    is_crm_online=False,
)

print dyn.make_whoami_request()

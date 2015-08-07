#!/usr/bin/env python
from dynamics import DynamicsCrmSettings


url = raw_input('Url: ')
username = raw_input('Username: ')
password = raw_input('Password: ')

dyn = DynamicsCrmSettings(
    url=url,
    username=username,
    password=password,
    is_crm_online=True,
)

users = dyn.get_users()
print len(users)

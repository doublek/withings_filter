#!/usr/bin/env python

import urllib, hashlib
import json

withings_base_url = 'http://wbsapi.withings.net/'
withings_once = withings_base_url + 'once?action=get'
withings_geturllist = withings_base_url + 'account?action=getuserslist&email=%s&hash=%s'

# XXX Lazy me :D
USER_EMAIL = 'karthikkrishnan.r@gmail.com'
# Hash calculated as follows:
# import hashlib
# password = 'password'
# hashlib.md5(password).hexdigest()
USER_PASSWORD_HASH = 'e9ec45c353659b99aa5586d96d32a466'

def get_once_magic_string():
    '''
    '''
    once_handle = urllib.urlopen(withings_once)
    once_data = once_handle.read()
    once_json = json.loads(once_data)
    if once_json['status'] != 0:
        return None
    return once_json['body']['once']


def authenticate_user(email, password_hash):
    '''Authenticate user against withings.'''
    once = get_once_magic_string()
    if once == None:
        return None
    print "Got once: %s" % once
    to_hash = '%s:%s:%s' % (email, password_hash, once)
    hash = hashlib.md5(to_hash).hexdigest()
    url = withings_geturllist % (email, hash)
    print "URL used is: %s" % url
    auth_handle = urllib.urlopen(url)
    auth_data = auth_handle.read()
    print auth_data


def main():
    authenticate_user(USER_EMAIL, USER_PASSWORD_HASH)

if __name__ == '__main__':
    main()

#!/usr/bin/env python
# Refer to file named COPYRIGHT in the directory where you found this file for
# copyright information

import sys
import urllib, hashlib
import json
import hashlib

withings_base_url = 'http://wbsapi.withings.net/'
withings_once = withings_base_url + 'once?action=get'
withings_geturllist = withings_base_url + 'account?action=getuserslist&email=%s&hash=%s'

def calculate_password_hash(password):
    '''Calculate the password md5 hash.'''

    return hashlib.md5(password).hexdigest()

def get_once_magic_string():
    '''
    Get the once magic string that the withings API required. This magic
    string will be used in all (or atleast most) subsequent requests.
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

    json_auth_data = json.loads(auth_data)
    print json.dumps(json_auth_data, indent=4)

    if json_auth_data['status'] != 0:
        print 'Error when contacting withings... Exiting...'
        return

    user_id = json_auth_data['body']['users'][0]['id']
    public_key = json_auth_data['body']['users'][0]['publickey']
    short_name = json_auth_data['body']['users'][0]['shortname'] 

    return user_id, public_key, short_name


def main():
    if len(sys.argv) != 3:
        print '''Error: Enough arguments not supplied..
Usage: withings_filter.py <username> <password>'''
        return

    password = sys.argv.pop()
    password_hash = calculate_password_hash(password)

    email = sys.argv.pop()

    print 'Processing for %s with password hash %s' % (
        email,
        password_hash
    )

    user_id, public_key, short_name = authenticate_user(email, password_hash)

    print 'UserID for %s is %d and publickey is %s' % (
        short_name,
        user_id,
        public_key,
    )


if __name__ == '__main__':
    main()

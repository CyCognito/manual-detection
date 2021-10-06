# MIT License

# Copyright (c) 2021 Cycognito

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import re
import requests
import sys

from bs4 import BeautifulSoup
from argparse import ArgumentParser

ACTION_ATTR = 'action'
FORM_TAG = 'form'
INPUT_TAG = 'input'
INPUT_TYPE = 'type'
PASSWORD_TYPE = 'password'
PLAINTEXT_PROTOCOL = 'http://'
PROTOCOL_DOMAIN_REG = re.compile(r'^( https?:// [a-zA-Z\d\-\.]+ (?:\:\d{1,5})? ) (?:/.*)?$',
                                 re.X)


def _get_form_action_url(form, start_url):
    action = form.get(ACTION_ATTR, start_url)
    if not action.lower().startswith('http'):
        # action is relative
        domain = PROTOCOL_DOMAIN_REG.findall(start_url).pop()
        action = f'{domain}{action}' if action.startswith('/') else f'{domain}/{action}'

    return action

def cyc_plaintext_authentication(form, start_url):
    return _get_form_action_url(form, start_url).startswith(PLAINTEXT_PROTOCOL)

def _has_password_input(form):
    return any(form_input.get(INPUT_TYPE) == PASSWORD_TYPE
               for form_input in form.select(INPUT_TAG))

def get_authentication_forms(response):
    bs = BeautifulSoup(response.content, features="html.parser")
    return tuple(form
                 for form in bs.select(FORM_TAG)
                 if _has_password_input(form))

def get_page(url, timeout):
    requests.packages.urllib3.disable_warnings()

    try:
        response = requests.get(url, timeout=timeout, verify=False)
        return response

    except requests.exceptions.Timeout:
        print("Request timed-out", file=sys.stderr)

    except Exception as error:
        print(f"Request failed with the following error:\n{error}", file=sys.stderr)
        # raise

def parse_args():
    parser = ArgumentParser()
    parser.add_argument(dest='url', metavar='URL', help='web server')
    parser.add_argument('-c', '--connection-timeout', metavar='TIMEOUT', type=int,
                        default=10, help='Set timeout in seconds (default is 10)')
    parser.add_argument('-r', '--read-timeout', metavar='TIMEOUT', type=int,
                        default=30, help='Set timeout in seconds (default is 30)')
    return parser.parse_args()

def main():
    args = parse_args()
    
    response = get_page(args.url, (args.connection_timeout, args.read_timeout))
    if response is None:
        return

    auth_forms = get_authentication_forms(response)
    if not auth_forms:
        print("Given URL doesn't contain any authentication form", file=sys.stderr)
        return

    print(f'Found {len(auth_forms)} authentication forms')

    found_issue = False
    for i, form in enumerate(auth_forms):
        if cyc_plaintext_authentication(form, args.url):
            found_issue = True
            print(f"Form #{i} (id='{form.get('id')}') has plaintext authentication")

    if not found_issue:
        print(f'None of the forms has plaintext authentication')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f"Errored with the following error:\n{error}", file=sys.stderr)
        # raise

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
import ssl
import sys

from argparse import ArgumentParser

PHP_HEADER_VERSION_REG = re.compile(r'PHP/(\d+\.\d+\.\d+)', re.I)
PHP_INFO_VERSION_REG = re.compile(r'PHP Version (\d+\.\d+\.\d+)', re.I)
PHP_URIS_REG = re.compile(r'(?:src|href)="(/[^"]+\.php)"')
URL_REG = re.compile(r'(https?://[^/]+)(/.*)?', re.I)
DEFAULT_PHP_INFO_URI = '/phpinfo.php'


class AnySslAdapter(requests.adapters.HTTPAdapter):
    """"Transport adapter that allows us to use any SSL."""
    def init_poolmanager(self, *args, **kwargs):
        ssl_context = ssl.create_default_context()

        # Sets up old and insecure TLSv1.
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1
        ssl_context.check_hostname = False
        ssl_context.set_ciphers('ALL:!aNULL:!eNULL:HIGH:!DH:!aNULL')
        kwargs["ssl_context"] = ssl_context

        return super().init_poolmanager(*args, **kwargs)


def _content_as_str(response):
    return response.content.decode('utf8'
                                   if response.encoding is None else
                                   response.encoding)

def php_version_from_headers(response):
    for header in response.headers.values():
        matches = PHP_HEADER_VERSION_REG.findall(header)
        if any(matches):
            return matches.pop()

    return None # explicit

def php_version_from_source(response):
    matches = PHP_INFO_VERSION_REG.findall(_content_as_str(response))
    if any(matches):
        return matches.pop()

    return None # explicit

def _get_php_version(response):
    return php_version_from_headers(response) or php_version_from_source(response)

def get_page(url, timeout, **kwargs):
    with requests.Session() as session:
        session.mount('https://', AnySslAdapter())
        session.verify = False
        response = session.get(url, timeout=timeout, **kwargs)
    return response

def get_php_uris(response):
    links = {DEFAULT_PHP_INFO_URI} # set
    links.update(PHP_URIS_REG.findall(_content_as_str(response)))
    return links

def get_php_verion(url, timeout):
    requests.packages.urllib3.disable_warnings()
    try:
        response = get_page(url, timeout, verify=False)
    except requests.exceptions.Timeout:
        print("Request timed-out", file=sys.stderr)
        return

    except requests.RequestException as error:
        if ('Max retries exceeded with url' in str(error)) \
                or isinstance(error, requests.exceptions.TooManyRedirects):
            try:
                response = get_page(url, timeout, verify=False, allow_redirects=False)
            except requests.exceptions.ConnectionError:
                print("Server is unreachable", file=sys.stderr)
                return

        else:
            return print("Connection was aborted by the server", file=sys.stderr)

    version = _get_php_version(response)
    if version is not None:
        return version

    for uri in get_php_uris(response):
        another_url = URL_REG.sub(f'\\1{uri}', url)
        if another_url == url:
            continue

        another_response = get_page(another_url, timeout)
        version = _get_php_version(another_response)
        if version:
            return version

    return None # explicit

def parse_args():
    parser = ArgumentParser()
    parser.add_argument(dest='url', metavar='URL', help='web server')
    parser.add_argument('-c', '--connection-timeout', metavar='TIMEOUT', type=int,
                        default=10, help='Set timeout in seconds (default is 10)')
    parser.add_argument('-r', '--read-timeout', metavar='TIMEOUT', type=int,
                        default=30, help='Set timeout in seconds (default is 30)')
    return parser.parse_args()

def check_cve_2018_20783(php_version):
    major, minor, patch = map(int, php_version.split('.'))
    return (
        major <= 5
        or (
            major == 5
            and (
                minor < 6
                or (minor == 6 and patch < 39)
            )
        )
        or (
            major == 7
            and (
                (minor == 0 and patch < 33)
                or (minor == 1 and patch < 25)
                or (minor == 2 and patch < 13)
            )
        )
    )

def main():
    args = parse_args()
    php_version = get_php_verion(args.url, (args.connection_timeout, args.read_timeout))
    if php_version is None:
        print("Failed to find any PHP version", file=sys.stderr)
    elif check_cve_2018_20783(php_version):
        print(f"PHP server vulnerable to CVE-2018-20783 (PHP-version={php_version})")
    else:
        print(f"Protected PHP server (PHP-version={php_version})")

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f"Failed with the following error:\n{error}", file=sys.stderr)
        # raise

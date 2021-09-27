"""
MIT License

Copyright (c) 2021 Cycognito

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import re
import socket

from argparse import ArgumentParser


OPENSSH_BANNER_REG = re.compile(r'^.*OpenSSH_(\d\.?\d?).*$')
SAFE_VERSION = 7.0
try:
    RST_ERROR_TYPE = ConnectionRefusedError
except NameError:
    RST_ERROR_TYPE = socket.error


def parse_args():
    parser = ArgumentParser()
    parser.add_argument(dest='ip', metavar='IP', help='IP address to check')
    parser.add_argument('-p', '--port', metavar='PORT', default=22, type=int,
                        help='Use given SSH port (default is 22)')
    parser.add_argument('-w', '--wait', dest='timeout', metavar='TIMEOUT',
                        default=5, type=int, help='Set timeout in seconds (default is 5)')
    return parser.parse_args()

def create_socket(timeout):
    sock = socket.socket()
    sock.settimeout(timeout)
    return sock

def get_banner(timeout, ip, port):
    sock = create_socket(timeout)
    try:
        sock.connect((ip, port))

    except socket.timeout:
        print('TCP connection to {}:{} timed out'.format(ip, port))
        return

    except RST_ERROR_TYPE:
        print('TCP connection to {}:{} was refused'.format(ip, port))
        return

    else:
        banner = sock.recv(1000)

    finally:
        sock.close()

    if not isinstance(banner, str):
        banner = banner.decode()

    return banner

def test(timeout, ip, port):
    banner = get_banner(timeout, ip, port)
    if banner is None:
        return

    match = OPENSSH_BANNER_REG.search(banner)
    if match and (float(match.groups()[0]) < SAFE_VERSION):
        version = match.groups()[0]
        print('Might be vulnerable to CVE-2015-6563 & CVE-2015-6564 '
              '(OpenSSH version is {})'.format(version))

    else:
        print('SSH server is safe (SSH banner is {})'.format(banner.strip()))

def main():
    args = parse_args()
    try:
        test(args.timeout, args.ip, args.port)
    except Exception as error:
        print('Testing failed with the following error:\n{}'.format(error))

if __name__ == '__main__':
    main()

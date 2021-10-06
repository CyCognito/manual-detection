# manual-detection
Contains scripts which may help to identify susceptiblea and vulnerable hosts or services

---
## test_openssh_vulns.py
A `python` script which test for both `CVE-2015-6563` & `CVE-2015-6564` (judging by the OpenSSH version).
Should work with both python2(.7) and python3.
#### Requirements:
None
#### Tested python versions:
- 2.7.16
- 3.7.3
---
## test_php_vulns
A `python` script which test for both `CVE-2018-20783` (judging by the PHP version).
Supports python3 only.
#### Requirements:
- requests==2.26.0
#### Tested python versions:
- 3.7.3
---
## plaintext_auth
A `python` script which test whether a given page (URL) has plain-text authentication
Supports python3 only.
#### Requirements:
- requests==2.26.0
- beautifulsoup4==4.10.0
#### Tested python versions:
- 3.7.3
---

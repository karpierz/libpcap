Changelog
=========

1.11.0b25 (2025-06-30)
----------------------
- Upgrade to the latest libpcap API 1.11.0-PRE
- Setup (dependencies) update.

1.11.0b24 (2025-05-15)
----------------------
- The distribution is now created using 'build' instead of 'setuptools'.
- Setup (dependencies) update (due to regressions in tox and setuptools).

1.11.0b23 (2025-05-04)
----------------------
- Minor fixes of tests.
- Setup (dependencies) update.

1.11.0b22 (2025-04-28)
----------------------
- Add support for Python 3.14
- Drop support for Python 3.9 (due to compatibility issues).
- Update readthedocs's python to version 3.13
- Update tox's base_python to version 3.13
- Upgrade to the latest libpcap API 1.11.0-PRE
- Setup (dependencies) update.

1.11.0b16 (2025-02-14)
----------------------
- Upgrade to the latest libpcap API 1.11.0-PRE
- Preliminary addition of (some) fuzz tests.
- Copyright year update.
- Setup (dependencies) update.

1.11.0b15 (2024-12-13)
----------------------
- Source distribution (\*.tar.gz now) is compliant with PEP-0625.
- 100% code linting.
- Tox configuration is now in native (toml) format.
- Setup (dependencies) update.

1.11.0b14 (2024-10-20)
----------------------
- Fix improper dependiencies for docs testenv.

1.11.0b13 (2024-10-20)
----------------------
- | Fix for improper use of ctypes.cdll.msvcrt._get_osfhandle.
  | Has been replaced by msvcrt.get_osfhandle.
  | Thank you very much crackevil@Github for the fix!
- Setup unification and (dependencies) update.

1.11.0b12 (2024-10-09)
----------------------
- Setup (dependencies) update.

1.11.0b11 (2024-09-30)
----------------------
- Drop support for Python 3.8
- Upgrade to the latest libpcap API 1.11.0-PRE
- Sync/upgrade of tests to the latest libpcap API 1.11.0-PRE
- Setup (dependencies) update.

1.11.0b10 (2024-08-13)
----------------------
- Add support for Python 3.13
- Improvements and cleanup for win32.
- Source code refactoring and cleanup.
- Setup (dependencies) update.

1.11.0b8 (2024-01-30)
---------------------
- Upgrade to the latest libpcap API 1.11.0-PRE
- Sync/upgrade of tests to the latest libpcap API 1.11.0-PRE
- Setup update (now based on tox >= 4.0).
- Add support for Python 3.12
- Drop support for Python 3.7
- Add support for PyPy 3.10
- Drop support for PyPy 3.7 and 3.8
- Copyright year update.
- Cleanup.

1.11.0b7 (2022-09-10)
---------------------
- Upgrade to the latest libpcap API 1.11.0-PRE
- Sync/upgrade of tests to the latest libpcap API 1.11.0-PRE
- Add nonblocktest.py
- Tox configuration has been moved to pyproject.toml

1.11.0b6 (2022-08-25)
---------------------
- Upgrade to the latest libpcap API 1.11.0-PRE
- Setup fixes and update.

1.11.0b5 (2022-07-28)
---------------------
- Upgrade to the latest libpcap API 1.11.0-PRE
- Add support for macOS x64 (thank you very much Erik Rainey emrainey@Github
  and lydia-hogan@Github!).
- Add support for Python 3.10 and 3.11
- Add support for PyPy 3.7, 3.8 and 3.9
- Setup update (currently based mainly on pyproject.toml).

1.11.0b4 (2022-01-10)
---------------------
- Drop support for Python 3.6.
- Copyright year update.
- Setup update.

1.11.0b2 (2021-11-10)
---------------------
- Upgrade to the latest libpcap API 1.11.0-PRE
- Copyright year update.
- *backward incompatibility* - libpcap.cfg is now a regular INI file.
- Setup update.

1.10.0b15 (2020-10-18)
----------------------
- Add support for Python 3.9.
- Drop support for Python 3.5.
- Removing dependence on atpublic.
- Ability to specify the backend programmatically.
- Establishing system's libpcap as default backend.
- Fixed a critical setup bug (thank you very much msrst@Github!).
- General update and cleanup.
- Fixed docs setup.

1.10.0b10 (2020-01-16)
----------------------
- Add support for Python 3.8.
- Drop support for Python 3.4.
- Drop support for Python 2.
- Upgrade to the latest libpcap API 1.10.0-PRE
- Establishing npcap as default backend.
- Internal npcap's dll-s have been removed due to ev. license problems.
- | Add support for Linux x64:
  | add internal tcpdump's libpcap.so v.1.9.1 with remote capture support.
  | system's tcpdump's libpcap.so can also be used (via libpcap.libpcap.cfg).
- Added ReadTheDocs config file.
- Setup update and cleanup.

1.10.0b5 (2019-09-16)
---------------------
- Upgrade to the latest libpcap API 1.10.0-PRE
- Upgrade npcap's libpcap dll-s to the 0.996
- Minor setup fixes and improvements.

1.10.0b3 (2019-02-15)
---------------------
- Upgrade to the latest libpcap API 1.10.0-PRE
- Upgrade npcap's libpcap dll-s to the 0.99rc9
- Update required setuptools version.
- Minor setup improvements.
- Updates of tests.

1.10.0b1 (2018-11-08)
---------------------
- Upgrade to the latest libpcap API 1.10.0-PRE
- Upgrade npcap's libpcap dll-s to the 0.99rc7
- Update required setuptools version.

1.0.0b14 (2018-05-09)
---------------------
- Update required setuptools version.

1.0.0b13 (2018-05-09)
---------------------
- Upgrade npcap's libpcap dll-s to the 0.99rc5

1.0.0b12 (2018-05-08)
---------------------
- Upgrade to the latest libpcap.

1.0.0b10 (2018-03-31)
---------------------
- Upgrade to the latest libpcap.
- Improve and simplify setup and packaging.
- Improve and update tests.

1.0.0b9 (2018-02-26)
--------------------
- Improve and simplify setup and packaging.

1.0.0b8 (2018-02-25)
--------------------
- Upgrade to the latest libpcap API 1.9.0
- Setup improvement.

1.0.0b7 (2017-12-18)
--------------------
- Fix the error of platform detecting (thanks to Dan ???).

1.0.0b6 (2017-10-11)
--------------------
- Upgrade to the libpcap API 1.9.0

1.0.0b5 (2017-10-08)
--------------------
- Upgrade to the libpcap API 1.8.1
- Add support for libpcap from `Npcap <https://nmap.org/npcap/>`__.

1.0.0b4 (2017-10-04)
--------------------
- Fourth beta release.

1.0.0b3 (2017-08-28)
--------------------
- Third beta release.

1.0.0b1 (2017-08-27)
--------------------
- First beta release.

1.0.0a16 (2017-08-26)
---------------------
- Next alpha release.

1.0.0a0 (2017-06-08)
--------------------
- First alpha release.

0.0.1 (2016-09-23)
------------------
- Initial release.

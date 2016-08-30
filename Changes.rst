Changes for v2.2.1 (2016-08-30)
===============================

-  Avoid using python-future; it has subdependencies that limit
   compatibility (#34)
-  Make test suite pass on 32-bit platforms (#30)
-  Timing attack resistance fix: don't reveal string length to attacker.
   Thanks to Eeo Jun (#28).
-  Support algorithm, digits, period parameters in provisioning\_uri.
   Thanks to Dionisio E Alonso (#33).
-  Minor style and packaging infrastructure fixes.

Changes for v2.2.0 (2016-08-30)
===============================

-  See v2.2.1

Version 2.1.0 (2016-05-02)
--------------------------
- Add extended range support to TOTP.verify. Thanks to Zeev Rotshtein (PR #19).
- Handle missing padding of encoded secret. Thanks to Kun Yan (#20).
- Miscellaneous fixes.

Version 2.0.1 (2015-09-28)
--------------------------
- Fix packaging issue in v2.0.0 that prevented installation with easy_install.

Version 2.0.0 (2015-08-22)
--------------------------
- The ``pyotp.HOTP.at()``, ``pyotp.TOTP.at()``, and
  ``pyotp.TOTP.now()`` methods now return strings instead of
  integers. Thanks to Rohan Dhaimade (PR #16).

Version 1.4.2 (2015-07-21)
--------------------------
- Begin tracking changes in change log.
- Update documentation.
- Introduce Travis CI integration.

Version 1.3.1 (2012-02-29)
--------------------------
- Initial release.

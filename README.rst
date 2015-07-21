PyOTP - The Python One-Time Password Library
============================================

PyOTP is a Python library for generating one time passwords according to `RFC 4226
<http://tools.ietf.org/html/rfc4226>`_ and the `HOTP RFC <http://tools.ietf.org/html/draft-mraihi-totp-timebased-00>`_,
ported from Mark Percival's `ROTP <https://github.com/mdp/rotp>`_.

This is compatible with Google Authenticator apps available for Android and iPhone, and now in use on GMail.

Quick overview of using One Time Passwords on your phone
--------------------------------------------------------

* OTPs involve a shared secret, stored both on the phone and the server
* OTPs can be generated on a phone without internet connectivity
* OTPs should always be used as a second factor of authentication(if your phone is lost, you account is still secured with a password)
* Google Authenticator allows you to store multiple OTP secrets and provision those using a QR Code(no more typing in the secret)

Installation
------------
::

    pip install pyotp

Usage
-----

Time based OTPs
~~~~~~~~~~~~~~~
::

    totp = pyotp.TOTP('base32secret3232')
    totp.now() # => 492039

    # OTP verified for current time
    totp.verify(492039) # => True
    time.sleep(30)
    totp.verify(492039) # => False

Counter-based OTPs
~~~~~~~~~~~~~~~~~~
::

    hotp = pyotp.HOTP('base32secret3232')
    hotp.at(0) # => 260182
    hotp.at(1) # => 55283
    hotp.at(1401) # => 316439

    # OTP verified with a counter
    hotp.verify(316439, 1401) # => True
    hotp.verify(316439, 1402) # => False

Generating a base32 Secret Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

    pyotp.random_base32() # returns a 16 character base32 secret. Compatible with Google Authenticator

Google Authenticator Compatible
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The library works with the Google Authenticator iPhone and Android app, and also includes the ability to generate
provisioning URI's for use with the QR Code scanner built into the app::

    totp.provisioning_uri("alice@google.com") # => 'otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP'
    hotp.provisioning_uri("alice@google.com", 0) # => 'otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=0'

This can then be rendered as a QR Code which can then be scanned and added to the users list of OTP credentials.

Working example
~~~~~~~~~~~~~~~

Scan the following barcode with your phone, using Google Authenticator

![QR Code for OTP](http://chart.apis.google.com/chart?cht=qr&chs=250x250&chl=otpauth%3A%2F%2Ftotp%2Falice%40google.com%3Fsecret%3DJBSWY3DPEHPK3PXP)

Now run the following and compare the output::

    import pyotp
    totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
    print "Current OTP: %s" % totp.now()

Links
~~~~~

* `Project home page (GitHub) <https://github.com/pyotp/pyotp>`_
* `Documentation (Read the Docs) <https://pyotp.readthedocs.org/en/latest/>`_
* `Package distribution (PyPI) <https://pypi.python.org/pypi/pyotp>`_
* `Change log <https://github.com/pyotp/pyotp/blob/master/Changes.rst>`_
* `ROTP <https://github.com/mdp/rotp>`_ - Original Ruby OTP library by `Mark Percival <https://github.com/mdp>`_
* `OTPHP <https://github.com/lelag/otphp>`_ - PHP port of ROTP by `Le Lag <https://github.com/lelag>`_

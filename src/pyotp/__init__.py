import random as _random

from pyotp.hotp import HOTP
from pyotp.otp import OTP
from pyotp.totp import TOTP
from . import utils

VERSION = '1.4.2'


def random_base32(length=16, random=_random.SystemRandom(),
                  chars=list('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')):
    return ''.join(
        random.choice(chars)
        for _ in range(length)
    )

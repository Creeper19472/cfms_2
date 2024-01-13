import pyotp
sec = pyotp.random_base32()

topt = pyotp.TOTP(sec)
import secrets
import string
from typing import Final

DEFAULT_PASSWORD_LENGTH: Final[int] = 16


def generate_password(
    length: int = DEFAULT_PASSWORD_LENGTH,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = False,
    symbols: str = string.punctuation,
) -> str:
    if length < [use_lowercase, use_uppercase, use_digits, use_symbols].count(True):
        raise ValueError("The password length is too short")

    alphabet = ""
    if use_lowercase:
        alphabet += string.ascii_lowercase
    if use_uppercase:
        alphabet += string.ascii_uppercase
    if use_digits:
        alphabet += string.digits
    if use_symbols:
        alphabet += symbols

    if len(alphabet) == 0:
        raise ValueError("No chars are selected to generate password")

    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            (any(c.islower() for c in password) if use_lowercase else True)
            and (any(c.isupper() for c in password) if use_uppercase else True)
            and (any(c.isdigit() for c in password) if use_digits else True)
            and (any(c in symbols for c in password) if use_symbols else True)
        ):
            return password

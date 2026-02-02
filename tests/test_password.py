import string

import pytest

from security_tools.password import DEFAULT_PASSWORD_LENGTH, generate_password


class TestPassword:
    def test_generate_password_with_default_params(self) -> None:
        new_password = generate_password()

        assert len(new_password) == DEFAULT_PASSWORD_LENGTH
        assert any(c.islower() for c in new_password)
        assert any(c.isupper() for c in new_password)
        assert any(c.isdigit() for c in new_password)

    @pytest.mark.parametrize(
        argnames=("length", "use_lowercase", "use_uppercase", "use_digits", "use_symbols", "symbols"),
        argvalues=[
            (DEFAULT_PASSWORD_LENGTH, True, True, True, True, string.punctuation),
            (DEFAULT_PASSWORD_LENGTH, True, True, True, True, "!@#$%^&*"),
            (8, True, True, True, False, string.punctuation),
            (32, True, True, True, False, string.punctuation),
            (DEFAULT_PASSWORD_LENGTH, False, True, True, True, string.punctuation),
            (DEFAULT_PASSWORD_LENGTH, True, False, True, True, string.punctuation),
            (DEFAULT_PASSWORD_LENGTH, True, True, False, True, string.punctuation),
            (DEFAULT_PASSWORD_LENGTH, True, False, False, False, string.punctuation),
            (DEFAULT_PASSWORD_LENGTH, False, True, False, False, string.punctuation),
            (DEFAULT_PASSWORD_LENGTH, False, False, True, False, string.punctuation),
            (DEFAULT_PASSWORD_LENGTH, False, False, False, True, string.punctuation),
        ],
    )
    def test_generate_password_with_different_params(
        self,
        length: int,
        use_lowercase: bool,
        use_uppercase: bool,
        use_digits: bool,
        use_symbols: bool,
        symbols: str,
    ) -> None:
        new_password = generate_password(
            length=length,
            use_lowercase=use_lowercase,
            use_uppercase=use_uppercase,
            use_digits=use_digits,
            use_symbols=use_symbols,
            symbols=symbols,
        )

        assert len(new_password) == length
        assert any(c.islower() for c in new_password) if use_lowercase else True
        assert any(c.isupper() for c in new_password) if use_uppercase else True
        assert any(c.isdigit() for c in new_password) if use_digits else True
        assert any(c in symbols for c in new_password) if use_symbols else True

    @pytest.mark.parametrize(
        argnames=("length", "use_lowercase", "use_uppercase", "use_digits", "use_symbols", "symbols"),
        argvalues=[
            (DEFAULT_PASSWORD_LENGTH, False, False, False, False, string.punctuation),
            (DEFAULT_PASSWORD_LENGTH, False, False, False, True, ""),
            (2, True, True, True, False, string.punctuation),
            (3, True, True, True, True, string.punctuation),
        ],
    )
    def test_generate_password_with_wrong_params(
        self,
        length: int,
        use_lowercase: bool,
        use_uppercase: bool,
        use_digits: bool,
        use_symbols: bool,
        symbols: str,
    ) -> None:
        with pytest.raises(ValueError):
            generate_password(
                length=length,
                use_lowercase=use_lowercase,
                use_uppercase=use_uppercase,
                use_digits=use_digits,
                use_symbols=use_symbols,
                symbols=symbols,
            )

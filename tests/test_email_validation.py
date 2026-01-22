from main import is_valid_email


def test_valid_email():
    assert is_valid_email("test@example.com")


def test_invalid_email():
    assert not is_valid_email("not-an-email")


from encryption import encrypt_message


def test_invalid_key_length():
    try:
        encrypt_message(b"short-key", b"test")
    except ValueError:
        print("Invalid key rejection: PASS")
        return

    print("Invalid key rejection: FAIL")


if __name__ == "__main__":
    test_invalid_key_length()

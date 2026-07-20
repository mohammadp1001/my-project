from main import hash_password, verify_password


def test_hash_and_verify_round_trip():
    hashed = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", hashed)


def test_verify_rejects_wrong_password():
    hashed = hash_password("correct horse battery staple")
    assert not verify_password("wrong password", hashed)


def test_hash_does_not_store_plaintext():
    password = "correct horse battery staple"
    hashed = hash_password(password)
    assert hashed != password

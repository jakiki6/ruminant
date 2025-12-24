from .buf import Buf

tests = {}


def test(group, name):

    def inner(func):
        if group not in tests:
            tests[group] = {}

        tests[group][name] = func
        return func

    return inner


def inv(func):

    def f():
        try:
            func()
        except Exception:
            return

        raise Exception("Test ran successfully when it shouldn't")

    return f


def assert_eq(a, b):
    assert a == b, f"Expected {b}, got {a}"


@test("Sanity", "simple-pass")
def sanity_simple_pass():
    pass


@test("Sanity", "inverted")
@inv
def sanity_inverted():
    # this should crash
    assert False


@test("Buffer", "from-bytes")
def buf_from_bytes():
    Buf(b"deadbeef")


@test("Buffer", "from-file")
def buf_from_file():
    Buf(open(__file__, "rb"))


@test("Buffer", "fail-from-string")
@inv
def buf_fail_from_string():
    Buf("deadbeef")


@test("Buffer", "ru8")
def buf_ru8():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru8(), 0x81)


@test("Buffer", "ru16")
def buf_ru16():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru16(), 0x8182)


@test("Buffer", "ru32")
def buf_ru32():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru32(), 0x81828384)


@test("Buffer", "ru64")
def buf_ru64():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru64(), 0x8182838485868788)


@test("Buffer", "ri8")
def buf_ri8():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri8(), -0x7f)


@test("Buffer", "ri16")
def buf_ri16():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri16(), -0x7e7e)


@test("Buffer", "ri32")
def buf_ri32():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri32(), -0x7e7d7c7c)


@test("Buffer", "ri64")
def buf_ri64():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri64(), -0x7e7d7c7b7a797878)


###
@test("Buffer", "ru8l")
def buf_ru8l():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru8l(), 0x81)


@test("Buffer", "ru16l")
def buf_ru16l():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru16l(), 0x8281)


@test("Buffer", "ru32l")
def buf_ru32l():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru32l(), 0x84838281)


@test("Buffer", "ru64l")
def buf_ru64l():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru64l(), 0x8887868584838281)


@test("Buffer", "ri8l")
def buf_ri8l():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri8l(), -0x7f)


@test("Buffer", "ri16l")
def buf_ri16l():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri16l(), -0x7d7f)


@test("Buffer", "ri32l")
def buf_ri32l():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri32l(), -0x7b7c7d7f)


@test("Buffer", "ri64l")
def buf_ri64l():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri64l(), -0x7778797a7b7c7d7f)

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


@test("Buffer", "rf16")
def buf_rf16():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf16(), -2.300739288330078e-05)


@test("Buffer", "rf32")
def buf_rf32():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf32(), -4.794317366894298e-38)


@test("Buffer", "rf64")
def buf_rf64():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf64(), -2.1597750994171683e-301)


@test("Buffer", "rf16l")
def buf_rf16l():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf16l(), -3.820657730102539e-05)


@test("Buffer", "rf32l")
def buf_rf32l():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf32l(), -3.091780090135418e-36)


@test("Buffer", "rf64l")
def buf_rf64l():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf64l(), -1.4249914579614907e-267)


@test("Buffer", "rf32 inf")
def buf_rf32_inf():
    buf = Buf(bytes.fromhex("7f800000"))
    assert_eq(buf.rf32(), float("inf"))


@test("Buffer", "rf32 nan")
def buf_rf32_nan():
    buf = Buf(bytes.fromhex("7f800001"))
    assert_eq(str(buf.rf32()), "nan")


@test("Buffer", "rs")
def buf_rs():
    buf = Buf(b"abcd")
    assert_eq(buf.rs(3), "abc")
    assert_eq(buf.tell(), 3)


@test("Buffer", "rh")
def buf_rh():
    buf = Buf(bytes.fromhex("01020304"))
    assert_eq(buf.rh(3), "010203")
    assert_eq(buf.tell(), 3)


@test("Buffer", "rzs")
def buf_rzs():
    buf = Buf(b"abcd\x00")
    assert_eq(buf.rzs(), "abcd")
    assert_eq(buf.tell(), 5)


@test("Buffer", "rzs with end as zero")
def buf_rzs_end_as_zero():
    buf = Buf(b"abcd")
    assert_eq(buf.rzs(), "abcd")
    assert_eq(buf.tell(), 5)


@test("Buffer", "overread")
@inv
def buf_overread():
    buf = Buf(bytes(7))
    buf.ru64()


@test("Buffer", "unit")
def buf_unit():
    buf = Buf(bytes(8))

    buf.pasunit(5)
    buf.ru32()
    assert_eq(buf.tell(), 4)
    assert_eq(buf.unit, 1)
    buf.sapunit()
    assert_eq(buf.tell(), 5)
    assert_eq(buf.unit, None)


@test("Buffer", "unit overread")
@inv
def buf_unit_overread():
    buf = Buf(bytes(8))

    buf.pasunit(5)
    buf.ru64()


@test("Buffer", "unit oversize")
@inv
def buf_unit_oversize():
    buf = Buf(bytes(8))
    buf.pasunit(9)


@test("Buffer", "unit stack")
def buf_unit_stack():
    buf = Buf(bytes(8))

    buf.pasunit(7)
    buf.pasunit(5)
    assert_eq(buf.unit, 5)
    buf.sapunit()
    assert_eq(buf.unit, 2)

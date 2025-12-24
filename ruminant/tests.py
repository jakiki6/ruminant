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
def f():
    pass


@test("Sanity", "inverted")
@inv
def f():
    # this should crash
    assert False


@test("Buffer", "from-bytes")
def f():
    Buf(b"deadbeef")


@test("Buffer", "from-file")
def f():
    Buf(open(__file__, "rb"))


@test("Buffer", "fail-from-string")
@inv
def f():
    Buf("deadbeef")


@test("Buffer", "ru8")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru8(), 0x81)


@test("Buffer", "ru16")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru16(), 0x8182)


@test("Buffer", "ru24")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru24(), 0x818283)


@test("Buffer", "ru32")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru32(), 0x81828384)


@test("Buffer", "ru64")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru64(), 0x8182838485868788)


@test("Buffer", "ri8")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri8(), -0x7f)


@test("Buffer", "ri16")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri16(), -0x7e7e)


@test("Buffer", "ri24")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri24(), -0x7e7d7d)


@test("Buffer", "ri32")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri32(), -0x7e7d7c7c)


@test("Buffer", "ri64")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri64(), -0x7e7d7c7b7a797878)


###
@test("Buffer", "ru8l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru8l(), 0x81)


@test("Buffer", "ru16l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru16l(), 0x8281)


@test("Buffer", "ru24l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru24l(), 0x838281)


@test("Buffer", "ru32l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru32l(), 0x84838281)


@test("Buffer", "ru64l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru64l(), 0x8887868584838281)


@test("Buffer", "ri8l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri8l(), -0x7f)


@test("Buffer", "ri16l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri16l(), -0x7d7f)


@test("Buffer", "ri24l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri24l(), -0x7c7d7f)


@test("Buffer", "ri32l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri32l(), -0x7b7c7d7f)


@test("Buffer", "ri64l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri64l(), -0x7778797a7b7c7d7f)


@test("Buffer", "rf16")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf16(), -2.300739288330078e-05)


@test("Buffer", "rf32")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf32(), -4.794317366894298e-38)


@test("Buffer", "rf64")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf64(), -2.1597750994171683e-301)


@test("Buffer", "rf16l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf16l(), -3.820657730102539e-05)


@test("Buffer", "rf32l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf32l(), -3.091780090135418e-36)


@test("Buffer", "rf64l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.rf64l(), -1.4249914579614907e-267)


@test("Buffer", "rf32-inf")
def f():
    buf = Buf(bytes.fromhex("7f800000"))
    assert_eq(buf.rf32(), float("inf"))


@test("Buffer", "rf32-nan")
def f():
    buf = Buf(bytes.fromhex("7f800001"))
    assert_eq(str(buf.rf32()), "nan")


@test("Buffer", "rs")
def f():
    buf = Buf(b"abcd")
    assert_eq(buf.rs(3), "abc")
    assert_eq(buf.tell(), 3)


@test("Buffer", "rh")
def f():
    buf = Buf(bytes.fromhex("01020304"))
    assert_eq(buf.rh(3), "010203")
    assert_eq(buf.tell(), 3)


@test("Buffer", "rzs")
def f():
    buf = Buf(b"abcd\x00efgh")
    assert_eq(buf.rzs(), "abcd")
    assert_eq(buf.tell(), 5)


@test("Buffer", "rzs-with-end-as-zero")
def f():
    buf = Buf(b"abcd")
    assert_eq(buf.rzs(), "abcd")
    assert_eq(buf.tell(), 5)


@test("Buffer", "rl")
def f():
    buf = Buf(b"abcd\nefgh")
    assert_eq(buf.rl(), b"abcd")
    assert_eq(buf.tell(), 5)


@test("Buffer", "rl-with-end-as-newline")
def f():
    buf = Buf(b"abcd")
    assert_eq(buf.rl(), b"abcd")
    assert_eq(buf.tell(), 4)


###


@test("Buffer", "ru8")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru8(), 0x81)


@test("Buffer", "ru16")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru16(), 0x8182)


@test("Buffer", "ru24")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru24(), 0x818283)


@test("Buffer", "ru32")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru32(), 0x81828384)


@test("Buffer", "ru64")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ru64(), 0x8182838485868788)


@test("Buffer", "ri8")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri8(), -0x7f)


@test("Buffer", "ri16")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri16(), -0x7e7e)


@test("Buffer", "ri24")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri24(), -0x7e7d7d)


@test("Buffer", "ri32")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri32(), -0x7e7d7c7c)


@test("Buffer", "ri64")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.ri64(), -0x7e7d7c7b7a797878)


@test("Buffer", "pu8l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pu8l(), 0x81)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pu16l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pu16l(), 0x8281)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pu24l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pu24l(), 0x838281)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pu32l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pu32l(), 0x84838281)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pu64l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pu64l(), 0x8887868584838281)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pi8l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pi8l(), -0x7f)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pi16l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pi16l(), -0x7d7f)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pi24l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pi24l(), -0x7c7d7f)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pi32l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pi32l(), -0x7b7c7d7f)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pi64l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pi64l(), -0x7778797a7b7c7d7f)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pf32")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pf32(), -4.794317366894298e-38)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pf64")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pf64(), -2.1597750994171683e-301)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pf32l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pf32l(), -3.091780090135418e-36)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pf64l")
def f():
    buf = Buf(bytes.fromhex("8182838485868788"))
    assert_eq(buf.pf64l(), -1.4249914579614907e-267)
    assert_eq(buf.tell(), 0)


@test("Buffer", "pf32-inf")
def f():
    buf = Buf(bytes.fromhex("7f800000"))
    assert_eq(buf.pf32(), float("inf"))
    assert_eq(buf.tell(), 0)


@test("Buffer", "pf32-nan")
def f():
    buf = Buf(bytes.fromhex("7f800001"))
    assert_eq(str(buf.pf32()), "nan")
    assert_eq(buf.tell(), 0)


@test("Buffer", "ps")
def f():
    buf = Buf(b"abcd")
    assert_eq(buf.ps(3), "abc")
    assert_eq(buf.tell(), 0)


@test("Buffer", "ph")
def f():
    buf = Buf(bytes.fromhex("01020304"))
    assert_eq(buf.ph(3), "010203")
    assert_eq(buf.tell(), 0)


@test("Buffer", "pzs")
def f():
    buf = Buf(b"abcd\x00efgh")
    assert_eq(buf.pzs(), "abcd")
    assert_eq(buf.tell(), 0)


@test("Buffer", "pzs-with-end-as-zero")
def f():
    buf = Buf(b"abcd")
    assert_eq(buf.pzs(), "abcd")
    assert_eq(buf.tell(), 0)


@test("Buffer", "pl")
def f():
    buf = Buf(b"abcd\nefgh")
    assert_eq(buf.pl(), b"abcd")
    assert_eq(buf.tell(), 0)


@test("Buffer", "pl-with-end-as-newline")
def f():
    buf = Buf(b"abcd")
    assert_eq(buf.pl(), b"abcd")
    assert_eq(buf.tell(), 0)


@test("Buffer", "overread")
@inv
def f():
    buf = Buf(bytes(7))
    buf.ru64()


@test("Buffer", "unit")
def f():
    buf = Buf(bytes(8))

    buf.pasunit(5)
    buf.ru32()
    assert_eq(buf.tell(), 4)
    assert_eq(buf.unit, 1)
    buf.sapunit()
    assert_eq(buf.tell(), 5)
    assert_eq(buf.unit, None)


@test("Buffer", "unit-overread")
@inv
def f():
    buf = Buf(bytes(8))

    buf.pasunit(5)
    buf.ru64()


@test("Buffer", "unit-oversize")
@inv
def f():
    buf = Buf(bytes(8))
    buf.pasunit(9)


@test("Buffer", "unit-stack")
def f():
    buf = Buf(bytes(8))

    buf.pasunit(7)
    buf.pasunit(5)
    assert_eq(buf.unit, 5)
    buf.sapunit()
    assert_eq(buf.unit, 2)

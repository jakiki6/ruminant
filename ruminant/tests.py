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
    if isinstance(a, int) and isinstance(b, int):
        assert a == b, f"Expected {b}, got {a} (i.e. {hex(a)})"
    else:
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


buffer_read_cases = [
    (Buf.ru8, Buf.pu8, 0x81, 1),
    (Buf.ru16, Buf.pu16, 0x8182, 2),
    (Buf.ru24, Buf.pu24, 0x818283, 3),
    (Buf.ru32, Buf.pu32, 0x81828384, 4),
    (Buf.rf32, Buf.pf32, -4.794317366894298e-38, 4),
    (Buf.ru64, Buf.pu64, 0x8182838485868788, 8),
    (Buf.rf64, Buf.pf64, -2.1597750994171683e-301, 8),
    (Buf.ri8, Buf.pi8, -0x7f, 1),
    (Buf.ri16, Buf.pi16, -0x7e7e, 2),
    (Buf.ri24, Buf.pi24, -0x7e7d7d, 3),
    (Buf.ri32, Buf.pi32, -0x7e7d7c7c, 4),
    (Buf.ri64, Buf.pi64, -0x7e7d7c7b7a797878, 8),
    (Buf.ru8l, Buf.pu8l, 0x81, 1),
    (Buf.ru16l, Buf.pu16l, 0x8281, 2),
    (Buf.ru24l, Buf.pu24l, 0x838281, 3),
    (Buf.ru32l, Buf.pu32l, 0x84838281, 4),
    (Buf.rf32l, Buf.pf32l, -3.091780090135418e-36, 4),
    (Buf.ru64l, Buf.pu64l, 0x8887868584838281, 8),
    (Buf.rf64l, Buf.pf64l, -1.4249914579614907e-267, 8),
    (Buf.ri8l, Buf.pi8l, -0x7f, 1),
    (Buf.ri16l, Buf.pi16l, -0x7d7f, 2),
    (Buf.ri24l, Buf.pi24l, -0x7c7d7f, 3),
    (Buf.ri32l, Buf.pi32l, -0x7b7c7d7f, 4),
    (Buf.ri64l, Buf.pi64l, -0x7778797a7b7c7d7f, 8),
    (lambda buf: buf.rs(4), lambda buf: buf.ps(4), "abcd", 4, b"abcdefgh", "rs", "ps"),
    (lambda buf: buf.rh(4), lambda buf: buf.ph(4), "81828384", 4, None, "rh", "ph"),
    (Buf.rzs, Buf.pzs, "abcd", 5, b"abcd\x00efgh"),
    (Buf.rzs, Buf.pzs, "abcd", 5, b"abcd", "rzs-end-as-zero", "pzs-end-as-zero"),
    (Buf.rl, Buf.pl, b"abcd", 5, b"abcd\nefgh", "rl-lf", "pl-lf"),
    (Buf.rl, Buf.pl, b"abcd", 6, b"abcd\r\nefgh", "rl-crlf", "pl-crlf"),
    (Buf.rl, Buf.pl, b"abcd", 5, b"abcd\refgh", "rl-cr", "pl-cr"),
    (Buf.rl, Buf.pl, b"abcd", 6, b"abcd\n\refgh", "rl-lfcr", "pl-lfcr"),
    (Buf.rl, Buf.pl, b"abcd", 4, b"abcd", "rl-end", "pl-end"),
    (Buf.rl, Buf.pl, b"abcd", 5, b"abcd\n", "rl-lfend", "pl-lfend"),
    (Buf.rl, Buf.pl, b"abcd", 5, b"abcd\r", "rl-crend", "pl-crend"),
    (
        Buf.rguid,
        Buf.pguid,
        "64636261-6665-6867-696a-6b6c6d6e6f70",
        16,
        b"abcdefghijklmnop",
    ),
]


def buf_instance(rf, pf, val, pos, buf_bytes=None, rname=None, pname=None):
    if buf_bytes is None:
        buf_bytes = bytes.fromhex("8182838485868788")
    if rname is None:
        rname = rf.__name__
    if pname is None:
        pname = pf.__name__

    @test("Buffer", rname)
    def f():
        buf = Buf(buf_bytes)
        assert_eq(rf(buf), val)
        assert_eq(buf.tell(), pos)

    @test("Buffer", pname)
    def f():
        buf = Buf(buf_bytes)
        assert_eq(pf(buf), val)
        assert_eq(buf.tell(), 0)


for instance in buffer_read_cases:
    buf_instance(*instance)


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

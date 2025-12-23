from . import buf

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
    buf.Buf(b"deadbeef")


@test("Buffer", "from-file")
def buf_from_file():
    buf.Buf(open(__file__, "rb"))


@test("Buffer", "fail-from-string")
@inv
def buf_fail_from_string():
    buf.Buf("deadbeef")

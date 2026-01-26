import os

modules = []


def register(cls):
    if cls.dev and os.environ.get("RUMINANT_DEV_MODE", "0") == "0":
        return cls

    if cls.__name__ in [x.__name__ for x in modules]:
        old_cls = None
        for x in modules:
            if x.__name__ == cls.__name__:
                old_cls = x
                break

        raise ValueError(f"Module {cls} already registered from {old_cls}!")

    modules.append(cls)
    modules.sort(key=lambda x: x.priority)

    return cls


class RuminantModule(object):
    priority = 0
    dev = False
    desc = ""

    def __init__(self, buf):
        self.buf = buf

    def identify(buf, ctx={}):
        return False

    def chew(self):
        self.buf.skip(self.buf.available())
        return {}

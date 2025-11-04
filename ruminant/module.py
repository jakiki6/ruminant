import os

modules = []


def register(cls):
    if cls.dev and os.environ.get("RUMINANT_DEV_MODE", "0") == "0":
        return cls

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

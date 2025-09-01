modules = []


def register(cls):
    modules.append(cls)
    modules.sort(key=lambda x: x.priority)

    return cls


class RuminantModule(object):
    priority = 0

    def __init__(self, buf):
        self.buf = buf

    def identify(buf, ctx={}):
        return False

    def chew(self):
        self.buf.skip(self.buf.available())
        return {}

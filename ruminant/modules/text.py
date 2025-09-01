from .. import module, utils
from . import chew
import zlib
import json


@module.register
class Utf8Module(module.RuminantModule):
    priority = 1

    def identify(buf, ctx):
        try:
            assert buf.available() < 1000000
            buf.peek(buf.available()).decode("utf-8")

            return True
        except:
            return False

    def chew(self):
        meta = {}
        meta["type"] = "text"

        content = self.buf.rs(self.buf.available())

        try:
            content = utils.xml_to_dict(content, fail=True)
            meta["decoder"] = "xml"
        except:
            try:
                assert content[0] == "{"
                content = json.loads(content)
                meta["decoder"] = "json"
            except:
                content = content.split("\n")
                meta["decoder"] = "lines"

        meta["data"] = content

        return meta

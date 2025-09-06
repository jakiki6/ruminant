from .. import module, utils
from . import chew
import json
import base64


@module.register
class Utf8Module(module.RuminantModule):
    priority = 1

    def identify(buf, ctx):
        try:
            assert buf.available() > 0 and buf.available() < 1000000
            buf.peek(buf.available()).decode("utf-8")

            return True
        except Exception:
            return False

    def chew(self):
        meta = {}
        meta["type"] = "text"

        content = self.buf.rs(self.buf.available())

        try:
            content = utils.xml_to_dict(content, fail=True)
            meta["decoder"] = "xml"
        except Exception:
            try:
                assert content[0] == "{"
                content = json.loads(content)
                meta["decoder"] = "json"
            except Exception:
                try:
                    blob = chew(base64.b64decode(content))
                    assert blob["type"] != "unknown"
                    content = blob
                    meta["decoder"] = "base64"
                except Exception:
                    content = content.split("\n")
                    meta["decoder"] = "lines"

        meta["data"] = content

        return meta

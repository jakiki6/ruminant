from .. import module, utils
from . import chew
from ..buf import Buf
from ..thirdparty import lzw

import re
import math
import base64


def png_decode(data, columns, rowlength):
    # based on https://github.com/py-pdf/pypdf/blob/47a7f8fae02aa06585f8c8338dcab647e2547917/pypdf/filters.py#L204
    # licensed under BSD-3
    # see https://github.com/py-pdf/pypdf/blob/47a7f8fae02aa06585f8c8338dcab647e2547917/LICENSE for attribution

    output = b""
    prev_rowdata = bytes(rowlength)
    bpp = (rowlength - 1) // columns
    for row in range(0, len(data), rowlength):
        rowdata = bytearray(data[row:row + rowlength])
        cmd = rowdata[0]

        match cmd:
            case 0:
                pass
            case 1:
                for i in range(bpp + 1, rowlength):
                    rowdata[i] = (rowdata[i] + rowdata[i - bpp]) % 256
            case 2:
                for i in range(1, rowlength):
                    rowdata[i] = (rowdata[i] + prev_rowdata[i]) % 256
            case 3:
                for i in range(1, bpp + 1):
                    floor = prev_rowdata[i] // 2
                    rowdata[i] = (rowdata[i] + floor) % 256
                for i in range(bpp + 1, rowlength):
                    left = rowdata[i - bpp]
                    floor = (left + prev_rowdata[i]) // 2
                    rowdata[i] = (rowdata[i] + floor) % 256
            case 4:
                for i in range(1, bpp + 1):
                    up = prev_rowdata[i]
                    paeth = up
                    rowdata[i] = (rowdata[i] + paeth) % 256
                for i in range(bpp + 1, rowlength):
                    left = rowdata[i - bpp]
                    up = prev_rowdata[i]
                    up_left = prev_rowdata[i - bpp]
                    p = left + up - up_left
                    dist_left = abs(p - left)
                    dist_up = abs(p - up)
                    dist_up_left = abs(p - up_left)
                    if dist_left <= dist_up and dist_left <= dist_up_left:
                        paeth = left
                    elif dist_up <= dist_up_left:
                        paeth = up
                    else:
                        paeth = up_left
                    rowdata[i] = (rowdata[i] + paeth) % 256
            case _:
                raise ValueError(f"Unsupported PNG predictor {cmd}")

        prev_rowdata = bytes(rowdata)
        output += rowdata[1:]

    return output


class ReparsePoint(Exception):
    pass


@module.register
class PdfModule(module.RuminantModule):
    TOKEN_PATTERN = re.compile(
        r"( << | >> | \[ | \] | /[^\s<>/\[\]()]+ | \d+\s+\d+\s+R | \d+\.\d+ | \d+ | \( (?: [^\\\)] | \\ . )* \) | <[0-9A-Fa-f\s]*> | true | false | null )",
        re.VERBOSE | re.DOTALL,
    )
    INDIRECT_OBJECT_PATTERN = re.compile(r"^(\d+) (\d+) R$")
    XREF_PATTERN = re.compile(r"^(\d{10}) (\d{5}) ([nf]).*$")

    def identify(buf, ctx):
        return buf.peek(5) == b"%PDF-"

    def chew(self):
        meta = {}
        meta["type"] = "pdf"

        meta["version"] = (self.buf.rl().decode("latin-1").split("-")[1])
        meta["binary-comment"] = self.buf.rl().hex()

        self.buf.seek(0, 2)
        while self.buf.peek(9) != b"startxref":
            self.buf.seek(-1, 1)

        self.buf.rl()
        xref_offset = int(self.buf.rl().decode("latin-1"))
        meta["xref-offset"] = xref_offset

        self.buf.seek(xref_offset)

        self.objects = {}
        self.queue = []
        self.compressed = []

        ver_15_offsets = []

        if self.buf.peek(4) == b"xref":
            self.buf.rl()

            obj_id = 0
            while True:
                line = self.buf.rl().decode("latin-1")

                if "trailer" in line:
                    while self.buf.peek(7) != b"trailer":
                        self.buf.seek(-1, 1)

                    self.buf.skip(7)

                    d = self.read_value(self.buf)

                    if "XRefStm" in d:
                        ver_15_offsets.append(d["XRefStm"])

                    if "Prev" in d:
                        self.buf.seek(d["Prev"])
                        self.buf.rl()
                        continue

                    break

                m = self.XREF_PATTERN.match(line)
                if m:
                    if m.group(3) == "n" and m.group(1) != "0000000000":
                        self.queue.append((int(m.group(1)), self.buf))

                    obj_id += 1
                else:
                    obj_id = int(line.split(" ")[0])
        else:
            # version 1.5+
            ver_15_offsets.append(self.buf.tell())

        for offset in ver_15_offsets:
            self.buf.seek(offset)
            self.parse_object(self.buf)

        while len(self.queue) + len(self.compressed):
            stuck = True
            if len(self.compressed):
                for compressed_id, compressed_index, compressed_buf in self.compressed[:]:
                    if compressed_id in self.objects:
                        try:
                            with compressed_buf:
                                compressed_buf.seek(
                                    self.objects[compressed_id][0]["offset"])
                                self.parse_object(compressed_buf,
                                                  packed=(compressed_index,
                                                          compressed_id))
                            self.compressed.remove(
                                (compressed_id, compressed_index,
                                 compressed_buf))
                            stuck = False
                        except ReparsePoint:
                            pass

            if len(self.queue):
                for i in range(0, len(self.queue)):
                    try:
                        offset, buf = self.queue[0]

                        with buf:
                            buf.seek(offset)
                            self.parse_object(self.buf)

                        self.queue.pop(0)
                        stuck = False
                        break

                    except ReparsePoint:
                        self.queue.append(self.queue.pop(0))

            if stuck:
                break

        for k in list(self.objects.keys()):
            if len(self.objects[k]) == 0:
                del self.objects[k]

        meta["objects"] = self.objects

        self.buf.skip(self.buf.available())

        return meta

    def resolve(self, value):
        if isinstance(value, str):
            m = self.INDIRECT_OBJECT_PATTERN.match(value)

            if m:
                obj_id, obj_gen = int(m.group(1)), int(m.group(2))

                if obj_id not in self.objects or obj_gen not in self.objects[
                        obj_id]:
                    raise ReparsePoint()

                return self.objects[obj_id][obj_gen]["value"]

        return value

    def parse_object(self, buf, packed=None, obj_id=None):
        obj = {}
        obj["offset"] = buf.tell()

        if obj_id is None:
            line = b""
            while not line.endswith(b"obj"):
                line += buf.read(1)

            line = line.decode("latin-1")

            while buf.peek(1) in (b" ", b"\r", b"\n"):
                self.buf.skip(1)

            obj_id, obj_generation, _ = line.split(" ")[:3]
        else:
            obj_generation = 0

        obj_id = int(obj_id)
        obj_generation = int(obj_generation)

        if packed is None:
            if obj_id not in self.objects:
                self.objects[obj_id] = {}

            if obj_generation in self.objects[obj_id]:
                return

        obj["value"] = self.read_value(buf)

        if isinstance(obj["value"], dict):
            if "Length" in obj["value"]:
                length = self.resolve(obj["value"]["Length"])

                line = b""
                while not line.endswith(b"stream"):
                    line = buf.rl()

                with buf.sub(length):
                    old_buf = buf

                    filters = self.resolve(obj["value"].get("Filter", []))
                    if isinstance(filters, str):
                        filters = [filters]

                    for filt in filters:
                        match filt:
                            case "/FlateDecode":
                                content = buf.read()

                                try:
                                    content = utils.zlib_decompress(content)
                                except Exception:
                                    obj["decompression-error"] = True

                                buf = Buf(content)
                            case "/LZWDecode":
                                buf = Buf(lzw.decompress(buf.read()))
                            case "/ASCIIHexDecode":
                                buf = Buf(
                                    bytes.fromhex(
                                        buf.read().rstrip(b"\n").split(
                                            b">")[0].decode("latin-1")))
                            case "/ASCII85Decode":
                                buf = Buf(
                                    base64.a85decode(
                                        buf.read().rstrip(b"\n").split(
                                            b">")[0].decode("latin-1")))
                            case "/DCTDecode" | "/CCITTFaxDecode":
                                pass
                            case _:
                                raise ValueError(f"Unknown filter '{filt}'")

                    if "DecodeParms" in obj["value"]:
                        params = self.resolve(obj["value"]["DecodeParms"])

                        if "Predictor" in params:
                            match params["Predictor"]:
                                case 0:
                                    pass
                                case 2:
                                    row_length = math.ceil(
                                        params["Columns"] *
                                        params.get("Colors", 1) *
                                        params.get("BitsPerComponent", 8) / 8)
                                    bpp = row_length // params["Columns"]

                                    data = bytearray(buf.read())
                                    for i in range(len(data)):
                                        if i % row_length >= bpp:
                                            data[i] = (data[i] +
                                                       data[i - bpp]) % 256

                                    buf = Buf(data)
                                case 10 | 11 | 12 | 13 | 14 | 15:
                                    buf = Buf(
                                        png_decode(
                                            buf.read(), params["Columns"],
                                            math.ceil(
                                                params["Columns"] *
                                                params.get("Colors", 1) *
                                                params.get(
                                                    "BitsPerComponent", 8) / 8)
                                            + 1))
                                case _:
                                    raise ValueError(
                                        f"Unknown predictor: {params['Predictor']}"
                                    )

                    if packed is not None:
                        buf.seek(
                            self.resolve(obj["value"].get("First", 0)) +
                            packed[0])
                        return self.parse_object(buf, obj_id=packed[1])

                    obj_type = self.resolve(obj["value"].get("Type"))
                    obj_subtype = self.resolve(obj["value"].get("Subtype"))

                    match obj_type, obj_subtype:
                        case "/Metadata", "/XML":
                            obj["data"] = utils.xml_to_dict(buf.read())
                        case "/XRef", _:
                            w0, w1, w2 = self.resolve(obj["value"]["W"])
                            index = self.resolve(obj["value"].get("Index", []))
                            if len(index) == 0:
                                index = [0, (1 << 64) - 1]

                            while buf.available():
                                f0 = int.from_bytes(buf.read(w0),
                                                    "big") if w0 else 1
                                f1 = int.from_bytes(buf.read(w1), "big")
                                f2 = int.from_bytes(buf.read(w2),
                                                    "big") if w2 else 0

                                if f0 == 1:
                                    self.queue.append((f1, old_buf))
                                    index[0] += 1
                                    index[1] -= 1

                                    if index[1] <= 0:
                                        index.pop(0)
                                        index.pop(0)
                                elif f0 == 2 and (f1 | f2):
                                    self.compressed.append((f1, f2, old_buf))

                            if "Prev" in obj["value"]:
                                self.queue.append(
                                    (self.resolve(obj["value"]["Prev"]),
                                     old_buf))
                        case "/ObjStm", _:
                            tokens = list(self.tokenize(buf.rs(buf.unit)))

                            values = []
                            while len(tokens) > 0:
                                values.append(self.parse_value(tokens))

                            obj["data"] = values
                        case None, _:
                            bak = buf.backup()

                            obj["data"] = chew(buf)
                            if obj["data"]["type"] in ("unknown", "text"):
                                try:
                                    with buf:
                                        buf.restore(bak)
                                        tokens = list(
                                            self.tokenize(buf.rs(buf.unit)))

                                        values = []
                                        while len(tokens) > 0:
                                            values.append(
                                                self.parse_value(tokens))

                                        obj["data"] = values
                                except Exception:
                                    pass
                        case _, _:
                            obj["data"] = chew(buf)

                    buf = old_buf

        if packed is None:
            self.objects[obj_id][obj_generation] = obj

        return obj

    def read_value(self, buf):
        d = b""
        level = 0

        while True:
            if buf.peek(6) == b"endobj":
                break

            if buf.peek(1) == b"(":
                d += buf.read(1)

                ilevel = 1
                while ilevel > 0 and buf.available() > 0:
                    chunk = buf.peek(4096)
                    if not (b"\\" in chunk or b"(" in chunk or b")" in chunk):
                        d += buf.read(4096)
                    else:
                        if buf.peek(1) == b"\\":
                            d += buf.read(2)
                        elif buf.peek(1) == b"(":
                            ilevel += 1
                            d += buf.read(1)
                        elif buf.peek(1) == b")":
                            ilevel -= 1
                            d += buf.read(1)
                        else:
                            d += buf.read(1)

            elif buf.peek(2) == b"<<":
                level += 1
                d += buf.read(1)
            elif buf.peek(2) == b">>":
                level -= 1
                d += buf.read(1)

                if level == 0:
                    d += buf.read(1)
                    break
            elif buf.peek(1) == b"[":
                level += 1
            elif buf.peek(1) == b"]":
                level -= 1

                if level == 0:
                    d += buf.read(1)
                    break

            d += buf.read(1)

        tokens = list(self.tokenize(d.decode("latin-1")))
        return self.parse_value(tokens)

    @classmethod
    def extract_balanced(cls, s):
        group = ""
        depth = 0
        while len(s):
            c, s = s[0], s[1:]
            group += c

            if c == "\\":
                group += s[0]
                s = s[1:]
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1

                if depth <= 0:
                    break

        return group, s

    @classmethod
    def tokenize(cls, s):
        while len(s):
            if s[0].isspace():
                s = s[1:]
            elif s[0] == "(":
                group, s = cls.extract_balanced(s)
                yield group
            else:
                match = cls.TOKEN_PATTERN.match(s)
                if match:
                    yield match.group()
                    s = s[len(match.group()):]
                else:
                    s = s[1:]

    @classmethod
    def parse_dict(cls, tokens):
        result = {}
        key = None

        while len(tokens):
            if tokens[0] == ">>":
                tokens.pop(0)
                return result
            if key is None:
                if not tokens[0].startswith("/"):
                    raise ValueError(
                        f"Expected key starting with /, got {tokens[0]}")
                key = tokens.pop(0)[1:]
            else:
                value = cls.parse_value(tokens)
                result[key] = value
                key = None
        raise ValueError("Unterminated dictionary")

    @classmethod
    def parse_array(cls, tokens):
        result = []
        while len(tokens):
            if tokens[0] == "]":
                tokens.pop(0)
                return result
            result.append(cls.parse_value(tokens))
        raise ValueError("Unterminated array")

    @classmethod
    def parse_value(cls, tokens):
        if len(tokens) == 0:
            return

        token = tokens.pop(0)

        if token == "<<":
            return cls.parse_dict(tokens)
        elif token == "[":
            return cls.parse_array(tokens)
        elif re.match(r"\d+\s+\d+\s+R", token):
            return token.strip()
        elif token in ("true", "false", "null"):
            return {"true": True, "false": False, "null": None}[token]
        elif re.match(r"\d+\.\d+", token):
            return float(token)
        elif token.isdigit():
            return int(token)
        elif token.startswith("("):
            _token = token[1:-1]
            token = ""
            while len(_token):
                if _token[0] == "\\":
                    n = ""
                    _token = _token[1:]
                    while len(_token) and _token[0] in "0123456789":
                        n += _token[0]
                        _token = _token[1:]

                    if len(n) > 0:
                        token += chr(int(n, 8))
                    else:
                        token += _token[0]
                        _token = _token[1:]
                else:
                    token += _token[0]
                    _token = _token[1:]

            if len(token) >= 2 and token[0] == "\xfe" and token[1] == "\xff":
                if len(token) >= 3 and token[2] == "\\":
                    # what the fuck apple
                    temp = token.encode("latin-1")[2:]
                    token = b""

                    while len(temp) >= 5:
                        token += temp[4:5]
                        temp = temp[5:]

                    token = token.decode("latin-1")
                elif len(token) % 2 == 0:
                    token = token.encode("latin-1").decode("utf-16")
            elif len(token) >= 2 and token[0] == "\xff" and token[
                    1] == "\xfe" and len(token) % 2 == 0:
                token = token.encode("latin-1").decode("utf-16le")

            return token.replace("\\(", "(").replace("\\)", ")")
        elif token.startswith("<"):
            return bytes.fromhex(token[1:-1].replace(" ", "")).hex()
        elif token.startswith("/"):
            return token
        else:
            raise ValueError(f"Unknown token: {token}")

from .. import module, utils
from . import chew
import tempfile
import sqlite3


@module.register
class WasmModule(module.RuminantModule):

    def identify(buf, ctx):
        return buf.peek(4) == b"\x00asm"

    def read_name(self):
        return self.buf.rs(self.buf.ruleb())

    def read_element(self, short=False):
        typ = self.buf.ru8()
        value = {}

        match typ:
            case 0x2b:
                value["type"] = "name"
                value["name"] = self.read_name()

                if short:
                    value = value["name"]
            case 0x60:
                value["type"] = "func"
                value["param"] = self.read_list(short)
                value["result"] = self.read_list(short)

                if short:
                    value = "(" + ", ".join(
                        value["param"]) + ") -> (" + ", ".join(
                            value["result"]) + ")"
            case 0x7c | 0x7d | 0x7e | 0x7f:
                value["type"] = "type"
                value["name"] = {
                    0x7c: "f64",
                    0x7d: "f32",
                    0x7e: "i64",
                    0x7f: "i32"
                }[typ]

                if short:
                    value = value["name"]
            case _:
                raise ValueError(f"Unknown type {typ}")

        return value

    def read_list(self, short=False):
        count = self.buf.ruleb()

        return [self.read_element(short) for i in range(0, count)]

    def chew(self):
        meta = {}
        meta["type"] = "wasm"

        self.buf.skip(4)
        meta["version"] = self.buf.ru32l()

        meta["sections"] = []
        while self.buf.available() > 0:
            section = {}

            section_id = self.buf.ru8()
            section_length = self.buf.ruleb()

            self.buf.pushunit()
            self.buf.setunit(section_length)

            section["id"] = None
            section["length"] = section_length
            section["data"] = {}
            match section_id:
                case 0x00:
                    section["id"] = "Custom"
                    section["data"]["name"] = self.read_name()

                    match section["data"]["name"]:
                        case "target_features":
                            section["data"]["features"] = self.read_list(
                                short=True)
                        case "producers":
                            section["data"]["fields"] = {}
                            for i in range(0, self.buf.ruleb()):
                                key = self.read_name()

                                section["data"]["fields"][key] = {}
                                for j in range(0, self.buf.ruleb()):
                                    key2 = self.read_name()
                                    section["data"]["fields"][key][
                                        key2] = self.read_name()
                        case "linking":
                            section["data"]["version"] = self.buf.ruleb()

                            match section["data"]["version"]:
                                case 2:
                                    section["data"]["subsections"] = []

                                    while self.buf.unit > 0:
                                        subsection = {}
                                        typ2 = self.buf.ru8()

                                        self.buf.pushunit()
                                        self.buf.setunit(self.buf.ruleb())

                                        match typ2:
                                            case 0x08:
                                                subsection[
                                                    "type"] = "WASM_SYMBOL_TABLE"
                                            case _:
                                                subsection[
                                                    "type"] = f"UNKNOWN (0x{hex(typ2)[2:].zfill(2)})"
                                                subsection["unknown"] = True

                                        self.buf.skipunit()
                                        self.buf.popunit()

                                        section["data"]["subsections"].append(
                                            subsection)

                                case _:
                                    section["unknown"] = True
                        case ".debug_str":
                            section["data"]["strings"] = []
                            while self.buf.unit > 0:
                                section["data"]["strings"].append(
                                    self.buf.rzs())

                            for i in range(0, len(section["data"]["strings"])):
                                if section["data"]["strings"][i].startswith(
                                        "_Z"):
                                    section["data"]["strings"][i] = {
                                        "raw":
                                        section["data"]["strings"][i],
                                        "demangled":
                                        utils.demangle(
                                            section["data"]["strings"][i])
                                    }
                        case _:
                            with self.buf.subunit():
                                section["data"]["blob"] = chew(self.buf)
                case 0x01:
                    section["id"] = "Type"
                    section["data"]["types"] = self.read_list(True)
                case _:
                    section[
                        "id"] = f"Unknown (0x{hex(section_id)[2:].zfill(2)})"
                    section["unknown"] = True

            self.buf.skipunit()
            self.buf.popunit()

            meta["sections"].append(section)

        return meta


@module.register
class TorrentModule(module.RuminantModule):

    def identify(buf, ctx):
        with buf:
            if buf.read(1) != b"d":
                return False

            for i in range(0, 3):
                c = buf.read(1)
                if c in b"0123456789":
                    pass
                elif c == b":":
                    return True
                else:
                    return False

            return False

    def chew(self):
        meta = {}
        meta["type"] = "magnet"

        meta["data"] = utils.read_bencode(self.buf)

        return meta


@module.register
class Sqlite3Module(module.RuminantModule):

    def identify(buf, ctx):
        return buf.peek(16) == b"SQLite format 3\x00"

    def chew(self):
        meta = {}
        meta["type"] = "sqlite3"

        self.buf.skip(16)

        meta["header"] = {}
        meta["header"]["page-size"] = self.buf.ru16()
        if meta["header"]["page-size"] == 1:
            meta["header"]["page-size"] = 65536
        meta["header"]["write-version"] = self.buf.ru8()
        meta["header"]["read-version"] = self.buf.ru8()
        meta["header"]["reserved-per-page"] = self.buf.ru8()
        meta["header"]["max-embedded-payload-fraction"] = self.buf.ru8()
        meta["header"]["min-embedded-payload-fraction"] = self.buf.ru8()
        meta["header"]["leaf-payload-fraction"] = self.buf.ru8()
        meta["header"]["file-change-count"] = self.buf.ru32()
        meta["header"]["page-count"] = self.buf.ru32()
        meta["header"]["first-freelist"] = self.buf.ru32()
        meta["header"]["freelist-count"] = self.buf.ru32()
        meta["header"]["schema-cookie"] = self.buf.ru32()
        meta["header"]["schema-format"] = self.buf.ru32()
        meta["header"]["default-page-cache-size"] = self.buf.ru32()
        meta["header"]["largest-broot-page"] = self.buf.ru32()
        meta["header"]["encoding"] = utils.unraw(self.buf.ru32(), 4, {
            1: "UTF-8",
            2: "UTF-16le",
            3: "UTF-16be"
        })
        meta["header"]["user-version"] = self.buf.ru32()
        meta["header"]["incremental-vaccum-mode"] = self.buf.ru32()
        meta["header"]["application-id"] = self.buf.ru32()
        meta["header"]["reserved"] = self.buf.rh(20)
        meta["header"]["version-valid-for"] = self.buf.ru32()
        meta["header"]["sqlite-version-number"] = self.buf.ru32()

        fd = tempfile.NamedTemporaryFile()
        self.buf.seek(0)
        to_copy = meta["header"]["page-size"] * meta["header"]["page-count"]
        while to_copy > 0:
            fd.write(self.buf.read(min(to_copy, 1 << 24)))
            to_copy = max(to_copy - (1 << 24), 0)

        db = sqlite3.connect(fd.name)
        cur = db.cursor()

        meta["schema"] = [
            x[0] for x in cur.execute("SELECT sql FROM sqlite_master")
        ]

        db.close()
        fd.close()

        return meta

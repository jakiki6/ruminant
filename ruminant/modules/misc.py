from .. import module
from . import chew


@module.register
class WasmModule(module.RuminantModule):

    def identify(buf, ctx):
        return buf.peek(4) == b"\x00asm"

    def read_name(self):
        return self.buf.rs(self.buf.ruleb())

    def read_element(self):
        typ = self.buf.ru8()
        value = {}

        match typ:
            case 0x2b:
                value["type"] = "name"
                value["value"] = self.read_name()
            case 0x60:
                value["type"] = "func"
                value["param"] = self.read_list()
                value["result"] = self.read_list()
            case 0x7c | 0x7d | 0x7e | 0x7f:
                value["type"] = "type"
                value["name"] = {
                    0x7c: "f64",
                    0x7d: "f32",
                    0x7e: "i64",
                    0x7f: "i32"
                }[typ]
            case _:
                raise ValueError(f"Unknown type {typ}")

        return value

    def read_list(self):
        count = self.buf.ruleb()

        return [self.read_element() for i in range(0, count)]

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
                            section["data"]["features"] = self.read_list()
                        case "producers":
                            section["data"]["fields"] = {}
                            for i in range(0, self.buf.ruleb()):
                                key = self.read_name()

                                section["data"]["fields"][key] = {}
                                for j in range(0, self.buf.ruleb()):
                                    key2 = self.read_name()
                                    section["data"]["fields"][key][
                                        key2] = self.read_name()
                        case _:
                            with self.buf.subunit():
                                section["data"]["blob"] = chew(self.buf)
                case 0x01:
                    section["id"] = "Type"
                    section["data"]["types"] = self.read_list()
                case _:
                    section[
                        "id"] = f"Unknown (0x{hex(section_id)[2:].zfill(2)})"
                    section["unknown"] = True

            self.buf.skipunit()
            self.buf.popunit()

            meta["sections"].append(section)

        return meta

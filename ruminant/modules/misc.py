from .. import module


@module.register
class WasmModule(module.RuminantModule):

    def identify(buf, ctx):
        return buf.peek(4) == b"\x00asm"

    def chew(self):
        meta = {}
        meta["type"] = "wasm"

        self.buf.skip(4)
        meta["version"] = self.buf.ru32l()

        meta["sections"] = []
        while self.buf.available() > 0:
            section = {}

            section_id = self.buf.ru8()

            section_length = 0
            c = self.buf.ru8()
            section_length = c & 0x7f
            shift = 7
            while c & 0x80:
                c = self.buf.ru8()
                section_length |= (c & 0x7f) << shift
                shift += 7

            self.buf.pushunit()
            self.buf.setunit(section_length)

            section["id"] = None
            section["length"] = section_length
            match section_id:
                case _:
                    section[
                        "id"] = f"Unknown (0x{hex(section_id)[2:].zfill(2)})"
                    section["unknown"] = True

            self.buf.skipunit()
            self.buf.popunit()

            meta["sections"].append(section)

        return meta

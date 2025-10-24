from .. import module, utils
from . import chew
import tempfile
import sqlite3
import datetime
import gzip
import zlib


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


@module.register
class JavaClassModule(module.RuminantModule):
    NAMES = [
        "nop", "aconst_null", "iconst_m1", "iconst_0", "iconst_1", "iconst_2",
        "iconst_3", "iconst_4", "iconst_5", "lconst_0", "lconst_1", "fconst_0",
        "fconst_1", "fconst_2", "dconst_0", "dconst_1", "bipush", "sipush",
        "ldc", "ldc_w", "ldc2_w", "iload", "lload", "fload", "dload", "aload",
        "iload_0", "iload_1", "iload_2", "iload_3", "lload_0", "lload_1",
        "lload_2", "lload_3", "fload_0", "fload_1", "fload_2", "fload_3",
        "dload_0", "dload_1", "dload_2", "dload_3", "aload_0", "aload_1",
        "aload_2", "aload_3", "iaload", "laload", "faload", "daload", "aaload",
        "baload", "caload", "saload", "istore", "lstore", "fstore", "dstore",
        "astore", "istore_0", "istore_1", "istore_2", "istore_3", "lstore_0",
        "lstore_1", "lstore_2", "lstore_3", "fstore_0", "fstore_1", "fstore_2",
        "fstore_3", "dstore_0", "dstore_1", "dstore_2", "dstore_3", "astore_0",
        "astore_1", "astore_2", "astore_3", "iastore", "lastore", "fastore",
        "dastore", "aastore", "bastore", "castore", "sastore", "pop", "pop2",
        "dup", "dup_x1", "dup_x2", "dup2", "dup2_x1", "dup2_x2", "swap",
        "iadd", "ladd", "fadd", "dadd", "isub", "lsub", "fsub", "dsub", "imul",
        "lmul", "fmul", "dmul", "idiv", "ldiv", "fdiv", "ddiv", "irem", "lrem",
        "frem", "drem", "ineg", "lneg", "fneg", "dneg", "ishl", "lshl", "ishr",
        "lshr", "iushr", "lushr", "iand", "land", "ior", "lor", "ixor", "lxor",
        "iinc", "i2l", "i2f", "i2d", "l2i", "l2f", "l2d", "f2i", "f2l", "f2d",
        "d2i", "d2l", "d2f", "i2b", "i2c", "i2s", "lcmp", "fcmpl", "fcmpg",
        "dcmpl", "dcmpg", "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle",
        "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt",
        "if_icmple", "if_acmpeq", "if_acmpne", "goto", "jsr", "ret",
        "tableswitch", "lookupswitch", "ireturn", "lreturn", "freturn",
        "dreturn", "areturn", "return", "getstatic", "putstatic", "getfield",
        "putfield", "invokevirtual", "invokespecial", "invokestatic",
        "invokeinterface", "invokedynamic", "new", "newarray", "anewarray",
        "arraylength", "athrow", "checkcast", "instanceof", "monitorenter",
        "monitorexit", "wide", "multianewarray", "ifnull", "ifnonnull",
        "goto_w", "jsr_w", "breakpoint", "reserved", "reserved", "reserved",
        "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
        "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
        "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
        "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
        "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
        "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
        "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
        "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
        "impdep1", "impdep2"
    ]

    def identify(buf, ctx):
        return buf.peek(4) == b"\xca\xfe\xba\xbe"

    def resolve(self, index):
        return self.meta["constants"].get(index - 1, None)

    def read_attributes(self, target):
        target["attribute-count"] = self.buf.ru16()
        target["attributes"] = {}

        for i in range(0, target["attribute-count"]):
            key = self.resolve(self.buf.ru16())

            self.buf.pushunit()
            self.buf.setunit(self.buf.ru32())

            match key:
                case "Code":
                    val = {}
                    val["max-stack"] = self.buf.ru16()
                    val["max-locals"] = self.buf.ru16()

                    self.buf.pushunit()
                    self.buf.setunit(self.buf.ru32())

                    val["code"] = {}
                    start = self.buf.tell()
                    wide = 0
                    while self.buf.unit > 0:
                        wide = max(0, wide - 1)

                        pc = self.buf.tell() - start
                        op = self.buf.ru8()
                        name = self.NAMES[op]

                        match op:
                            case 0x15 | 0x16 | 0x17 | 0x18 | 0x19 | 0x36 | 0x37 | 0x38 | 0x39 | 0x3a:
                                name = [
                                    name,
                                    self.buf.ri16()
                                    if wide else self.buf.ri8()
                                ]
                            case 0x10 | 0xbc:
                                name = [name, self.buf.ri8()]
                            case 0x11 | 0x99 | 0x9a | 0x9b | 0x9c | 0x9d | 0x9e | 0x9f | 0xa0 | 0xa1 | 0xa2 | 0xa3 | 0xa4 | 0xa5 | 0xa6 | 0xa7 | 0xa8 | 0xc6 | 0xc7:
                                name = [name, self.buf.ri16()]
                            case 0x13 | 0x14 | 0xb2 | 0xb3 | 0xb4 | 0xb5 | 0xb6 | 0xb7 | 0xb8 | 0xbb | 0xbd | 0xc0 | 0xc1:
                                name = [name, self.buf.ru16()]
                            case 0xc8 | 0xc9:
                                name = [name, self.buf.ri32()]
                            case 0xba:
                                name = [name, self.buf.ru16(), self.buf.ru16()]
                            case 0xb9:
                                name = [
                                    name,
                                    self.buf.ru16(),
                                    self.buf.ru8(),
                                    self.buf.ru8()
                                ]
                            case 0xc5:
                                name = [name, self.buf.ru16(), self.buf.ru8()]
                            case 0x84:
                                name = [
                                    name,
                                    self.buf.ru8(),
                                    self.buf.ri16()
                                    if wide else self.buf.ri8()
                                ]
                            case 0x12:
                                name = [name, self.buf.ru8()]
                            case 0xaa:
                                while (self.buf.tell() - start) % 4 != 0:
                                    self.buf.skip(1)

                                name = [
                                    name,
                                    self.buf.ru32(),
                                    self.buf.ru32(),
                                    self.buf.ru32()
                                ]

                                name.append([
                                    self.buf.ru32()
                                    for i in range(0, name[3] - name[2] + 1)
                                ])
                            case 0xab:
                                while (self.buf.tell() - start) % 4 != 0:
                                    self.buf.skip(1)

                                name = [name, self.buf.ru32(), self.buf.ru32()]

                                name.append([(self.buf.ru32(), self.buf.ru32())
                                             for i in range(0, name[2])])
                            case 0xc4:
                                wide = 2

                        match op:
                            case 0x12 | 0x13 | 0x14 | 0xb2 | 0xb3 | 0xb4 | 0xb5 | 0xb6 | 0xb7 | 0xb8 | 0xb9 | 0xba | 0xbb | 0xbd | 0xc0 | 0xc1:
                                name[1] = self.resolve(name[1])

                        if isinstance(name, list):
                            name = name[0] + " " + ", ".join(
                                [str(x) for x in name[1:]])

                        val["code"][pc] = name

                    self.buf.skipunit()
                    self.buf.popunit()

                    val["exception-table-entry-count"] = self.buf.ru16()
                    val["exception-table-entries"] = []
                    for i in range(0, val["exception-table-entry-count"]):
                        ex = {}
                        ex["start-pc"] = self.buf.ru16()
                        ex["end-pc"] = self.buf.ru16()
                        ex["handler-pc"] = self.buf.ru16()
                        ex["catch-type"] = self.resolve(self.buf.ru16())

                        val["exception-table-entries"].append(ex)

                    self.read_attributes(val)
                case "LineNumberTable":
                    val = {}
                    for i in range(0, self.buf.ru16()):
                        key2 = self.buf.ru16()
                        val[key2] = self.buf.ru16()
                case "SourceFile":
                    val = self.resolve(self.buf.ru16())
                case "LocalVariableTable":
                    val = []
                    for i in range(0, self.buf.ru16()):
                        val.append({
                            "start-pc": self.buf.ru16(),
                            "length": self.buf.ru16(),
                            "name": self.resolve(self.buf.ru16()),
                            "descriptor": self.resolve(self.buf.ru16()),
                            "index": self.buf.ru16()
                        })
                case _:
                    val = self.buf.rh(self.buf.unit)

            self.buf.skipunit()
            self.buf.popunit()

            target["attributes"][key] = val

    def chew(self):
        meta = {}
        self.meta = meta

        meta["type"] = "java-class"

        self.buf.skip(4)

        meta["version"] = {}
        meta["version"]["minor"] = self.buf.ru16()
        meta["version"]["major"] = utils.unraw(
            self.buf.ru16(), 2, {
                45: "JDK 1.1",
                46: "JDK 1.2",
                47: "JDK 1.3",
                48: "JDK 1.4",
                49: "Java SE 5.0",
                50: "Java SE 6.0",
                51: "Java SE 7",
                52: "Java SE 8",
                53: "Java SE 9",
                54: "Java SE 10",
                55: "Java SE 11",
                56: "Java SE 12",
                57: "Java SE 13",
                58: "Java SE 14",
                59: "Java SE 15",
                60: "Java SE 16",
                61: "Java SE 17",
                62: "Java SE 18",
                63: "Java SE 19",
                64: "Java SE 20",
                65: "Java SE 21",
                66: "Java SE 22",
                67: "Java SE 23",
                68: "Java SE 24",
                69: "Java SE 25"
            })

        meta["constant-count"] = self.buf.ru16() - 1

        skip = False
        meta["constants"] = {}
        for i in range(0, meta["constant-count"]):
            if skip:
                skip = False
                continue
            const = None

            tag = self.buf.ru8()
            match tag:
                case 1:
                    const = self.buf.rs(self.buf.ru16())
                case 3:
                    const = self.buf.ri32()
                case 4:
                    const = self.buf.rf32()
                case 5:
                    const = self.buf.ri64()
                    skip = True
                case 6:
                    const = self.buf.rf64()
                    skip = True
                case 7:
                    const = ["class-ref", {"name": self.buf.ru16()}]
                case 8:
                    const = ["string-ref", {"value": self.buf.ru16()}]
                case 9:
                    const = [
                        "field-ref", {
                            "class": self.buf.ru16(),
                            "name-and-type": self.buf.ru16()
                        }
                    ]
                case 10:
                    const = [
                        "method-ref", {
                            "class": self.buf.ru16(),
                            "name-and-type": self.buf.ru16()
                        }
                    ]
                case 11:
                    const = [
                        "interface-method-ref", {
                            "class": self.buf.ru16(),
                            "name-and-type": self.buf.ru16()
                        }
                    ]
                case 12:
                    const = [
                        "name-and-type", {
                            "name": self.buf.ru16(),
                            "type": self.buf.ru16()
                        }
                    ]
                case 15:
                    const = [
                        "method-handle", {
                            "type": self.buf.ru8(),
                            "index": self.buf.ru16()
                        }
                    ]
                case 16:
                    const = ["method-type", {"type": self.buf.ru16()}]
                case 18:
                    const = [
                        "invokedynamic", {
                            "bootstrap-method": self.buf.ru16(),
                            "name-and-type": self.buf.ru16()
                        }
                    ]
                case _:
                    raise ValueError(f"Unknown constant type {tag}")

            meta["constants"][i if not skip else i + 1] = const

        for v in meta["constants"].values():
            if isinstance(v, list):
                for k, v2 in v[1].items():
                    if v[0] == "method-handle" and k == "type":
                        continue

                    v[1][k] = self.resolve(v2)

        flags = self.buf.ru16()
        meta["access-flags"] = {
            "raw": flags,
            "public": bool(flags & (1 << 0)),
            "final": bool(flags & (1 << 4)),
            "super": bool(flags & (1 << 5)),
            "interface": bool(flags & (1 << 9)),
            "abstract": bool(flags & (1 << 10))
        }

        meta["this-class"] = self.resolve(self.buf.ru16())
        meta["super-class"] = self.resolve(self.buf.ru16())

        meta["interface-count"] = self.buf.ru16()
        meta["interfaces"] = []
        for i in range(0, meta["interface-count"]):
            meta["interfaces"].append(self.resolve(self.buf.ru16()))

        meta["field-count"] = self.buf.ru16()
        meta["fields"] = []
        for i in range(0, meta["field-count"]):
            field = {}

            flags = self.buf.ru16()
            field["flags"] = {
                "raw": flags,
                "public": bool(flags & (1 << 0)),
                "private": bool(flags & (1 << 1)),
                "protected": bool(flags & (1 << 2)),
                "static": bool(flags & (1 << 3)),
                "final": bool(flags & (1 << 4)),
                "volatile": bool(flags & (1 << 6)),
                "transient": bool(flags & (1 << 7)),
                "synthetic": bool(flags & (1 << 12)),
                "enum": bool(flags & (1 << 14))
            }

            field["name"] = self.resolve(self.buf.ru16())
            field["descriptor"] = self.resolve(self.buf.ru16())

            self.read_attributes(field)

            meta["fields"].append(field)

        meta["method-count"] = self.buf.ru16()
        meta["methods"] = []
        for i in range(0, meta["method-count"]):
            method = {}

            flags = self.buf.ru16()
            method["flags"] = {
                "raw": flags,
                "public": bool(flags & (1 << 0)),
                "private": bool(flags & (1 << 1)),
                "protected": bool(flags & (1 << 2)),
                "static": bool(flags & (1 << 3)),
                "final": bool(flags & (1 << 4)),
                "synchronized": bool(flags & (1 << 5)),
                "bridge": bool(flags & (1 << 6)),
                "varargs": bool(flags & (1 << 7)),
                "native": bool(flags & (1 << 8)),
                "abstract": bool(flags & (1 << 10)),
                "strict": bool(flags & (1 << 11)),
                "synthetic": bool(flags & (1 << 12))
            }

            method["name"] = self.resolve(self.buf.ru16())
            method["descriptor"] = self.resolve(self.buf.ru16())

            self.read_attributes(method)

            meta["methods"].append(method)

        self.read_attributes(meta)

        return meta


@module.register
class ElfModule(module.RuminantModule):

    def identify(buf, ctx):
        return buf.peek(4) == b"\x7fELF"

    def hex(self, val):
        return {
            "raw": val,
            "hex": "0x" + hex(val)[2:].zfill(16 if self.wide else 8)
        }

    def chew(self):
        meta = {}
        meta["type"] = "elf"

        self.buf.skip(4)

        meta["header"] = {}
        meta["header"]["class"] = utils.unraw(self.buf.ru8(), 1, {
            1: "32-bit",
            2: "64-bit"
        })
        self.wide = meta["header"]["class"]["raw"] != 1

        meta["header"]["data"] = utils.unraw(self.buf.ru8(), 1, {
            1: "little endian",
            2: "big endian"
        })
        self.little = meta["header"]["data"]["raw"] == 1

        meta["header"]["version"] = self.buf.ru8()
        meta["header"]["abi"] = utils.unraw(
            self.buf.ru8(), 1, {
                0x00: "System V",
                0x01: "HP-UX",
                0x02: "NetBSD",
                0x03: "Linux",
                0x04: "GNU Hurd",
                0x06: "Solaris",
                0x07: "AIX (Monterey)",
                0x08: "IRIX",
                0x09: "FreeBSD",
                0x0A: "Tru64",
                0x0B: "Novell Modesto",
                0x0C: "OpenBSD",
                0x0D: "OpenVMS",
                0x0E: "NonStop Kernel",
                0x0F: "AROS",
                0x10: "FenixOS",
                0x11: "Nuxi CloudABI",
                0x12: "Stratus Technologies OpenVOS"
            })
        meta["header"]["abi-version"] = self.buf.ru8()
        meta["header"]["padding"] = self.buf.rh(7)
        meta["header"]["type"] = utils.unraw(
            self.buf.ru16l() if self.little else self.buf.ru16(), 2, {
                0x00: "ET_NONE",
                0x01: "ET_REL",
                0x02: "ET_EXEC",
                0x03: "ET_DYN",
                0x04: "ET_CORE"
            })
        meta["header"]["machine"] = utils.unraw(
            self.buf.ru16l() if self.little else self.buf.ru16(), 2, {
                0x00: "None",
                0x01: "AT&T WE 32100",
                0x02: "SPARC",
                0x03: "x86",
                0x04: "Motorola 68000 (M68k)",
                0x05: "Motorola 88000 (M88k)",
                0x06: "Intel MCU",
                0x07: "Intel 80860",
                0x08: "MIPS",
                0x09: "IBM System/370",
                0x0a: "MIPS RS3000 Little-endian",
                0x0b: "Reserved",
                0x0c: "Reserved",
                0x0d: "Reserved",
                0x0e: "Reserved",
                0x0f: "Hewlett-Packard PA-RISC",
                0x13: "Intel 80960",
                0x14: "PowerPC",
                0x15: "PowerPC (64-bit)",
                0x16: "S390, including S390x",
                0x17: "IBM SPU/SPC",
                0x18: "Reserved",
                0x19: "Reserved",
                0x1a: "Reserved",
                0x1b: "Reserved",
                0x1c: "Reserved",
                0x1d: "Reserved",
                0x1e: "Reserved",
                0x1f: "Reserved",
                0x20: "Reserved",
                0x21: "Reserved",
                0x22: "Reserved",
                0x23: "Reserved",
                0x24: "NEC V800",
                0x25: "Fujitsu FR20",
                0x26: "TRW RH-32",
                0x27: "Motorola RCE",
                0x28: "Arm (up to Armv7/AArch32)",
                0x29: "Digital Alpha",
                0x2a: "SuperH",
                0x2b: "SPARC Version 9",
                0x2c: "Siemens TriCore embedded processor",
                0x2d: "Argonaut RISC Core",
                0x2e: "Hitachi H8/300",
                0x2f: "Hitachi H8/300H",
                0x30: "Hitachi H8S",
                0x31: "Hitachi H8/500",
                0x32: "IA-64",
                0x33: "Stanford MIPS-X",
                0x34: "Motorola ColdFire",
                0x35: "Motorola M68HC12",
                0x36: "Fujitsu MMA Multimedia Accelerator",
                0x37: "Siemens PCP",
                0x38: "Sony nCPU embedded RISC processor",
                0x39: "Denso NDR1 microprocessor",
                0x3a: "Motorola Star*Core processor",
                0x3b: "Toyota ME16 processor",
                0x3c: "STMicroelectronics ST100 processor",
                0x3d: "Advanced Logic Corp. TinyJ embedded processor family",
                0x3e: "AMD x86-64",
                0x3f: "Sony DSP Processor",
                0x40: "Digital Equipment Corp. PDP-10",
                0x41: "Digital Equipment Corp. PDP-11",
                0x42: "Siemens FX66 microcontroller",
                0x43: "STMicroelectronics ST9+ 8/16-bit microcontroller",
                0x44: "STMicroelectronics ST7 8-bit microcontroller",
                0x45: "Motorola MC68HC16 Microcontroller",
                0x46: "Motorola MC68HC11 Microcontroller",
                0x47: "Motorola MC68HC08 Microcontroller",
                0x48: "Motorola MC68HC05 Microcontroller",
                0x49: "Silicon Graphics SVx",
                0x4a: "STMicroelectronics ST19 8-bit microcontroller",
                0x4b: "Digital VAX",
                0x4c: "Axis Communications 32-bit embedded processor",
                0x4d: "Infineon Technologies 32-bit embedded processor",
                0x4e: "Element 14 64-bit DSP Processor",
                0x4f: "LSI Logic 16-bit DSP Processor",
                0x8c: "TMS320C6000 Family",
                0xaf: "MCST Elbrus e2k",
                0xb7: "Arm 64-bits (Armv8/AArch64)",
                0xdc: "Zilog Z80",
                0xf3: "RISC-V",
                0xf7: "Berkeley Packet Filter",
                0x101: "WDC 65C816",
                0x102: "LoongArch"
            })

        meta["header"]["version2"] = self.buf.ru32l(
        ) if self.little else self.buf.ru32()
        meta["header"]["entry-point"] = self.hex((self.buf.ru64l(
        ) if self.little else self.buf.ru64()) if self.wide else (
            self.buf.ru32l() if self.little else self.buf.ru32()))
        meta["header"]["phoff"] = (
            self.buf.ru64l()
            if self.little else self.buf.ru64()) if self.wide else (
                self.buf.ru32l() if self.little else self.buf.ru32())
        meta["header"]["shoff"] = (
            self.buf.ru64l()
            if self.little else self.buf.ru64()) if self.wide else (
                self.buf.ru32l() if self.little else self.buf.ru32())
        meta["header"]["flags"] = self.buf.ru32l(
        ) if self.little else self.buf.ru32()
        meta["header"]["ehsize"] = self.buf.ru16l(
        ) if self.little else self.buf.ru16()
        meta["header"]["phentsize"] = self.buf.ru16l(
        ) if self.little else self.buf.ru16()
        meta["header"]["phnum"] = self.buf.ru16l(
        ) if self.little else self.buf.ru16()
        meta["header"]["shentsize"] = self.buf.ru16l(
        ) if self.little else self.buf.ru16()
        meta["header"]["shnum"] = self.buf.ru16l(
        ) if self.little else self.buf.ru16()
        meta["header"]["shstrndx"] = self.buf.ru16l(
        ) if self.little else self.buf.ru16()

        self.buf.seek(meta["header"]["phoff"])
        meta["program-headers"] = []
        for i in range(0, meta["header"]["phnum"]):
            ph = {}
            ph["type"] = utils.unraw(
                self.buf.ru32l() if self.little else self.buf.ru32(), 2, {
                    0x00000000: "PT_NULL",
                    0x00000001: "PT_LOAD",
                    0x00000002: "PT_DYNAMIC",
                    0x00000003: "PT_INTERP",
                    0x00000004: "PT_NOTE",
                    0x00000005: "PT_SHLIB",
                    0x00000006: "PT_PHDR",
                    0x00000007: "PT_TLS",
                    0x6474e550: "PT_GNU_EH_FRAME",
                    0x6474e551: "PT_GNU_STACK",
                    0x6474e552: "PT_GNU_RELRO",
                    0x6474e553: "PT_GNU_PROPERTY"
                })

            if self.wide:
                ph["flags"] = self.buf.ru32l(
                ) if self.little else self.buf.ru32()

            ph["offset"] = (
                self.buf.ru64l()
                if self.little else self.buf.ru64()) if self.wide else (
                    self.buf.ru32l() if self.little else self.buf.ru32())
            ph["vaddr"] = self.hex((self.buf.ru64l(
            ) if self.little else self.buf.ru64()) if self.wide else (
                self.buf.ru32l() if self.little else self.buf.ru32()))
            ph["paddr"] = self.hex((self.buf.ru64l(
            ) if self.little else self.buf.ru64()) if self.wide else (
                self.buf.ru32l() if self.little else self.buf.ru32()))
            ph["filesz"] = (
                self.buf.ru64l()
                if self.little else self.buf.ru64()) if self.wide else (
                    self.buf.ru32l() if self.little else self.buf.ru32())
            ph["memsz"] = (
                self.buf.ru64l()
                if self.little else self.buf.ru64()) if self.wide else (
                    self.buf.ru32l() if self.little else self.buf.ru32())

            if not self.wide:
                ph["flags"] = self.buf.ru32l(
                ) if self.little else self.buf.ru32()

            ph["flags"] = {"raw": ph["flags"], "names": []}

            if bool(ph["flags"]["raw"] & 0x01):
                ph["flags"]["names"].append("PF_X")
            if bool(ph["flags"]["raw"] & 0x02):
                ph["flags"]["names"].append("PF_W")
            if bool(ph["flags"]["raw"] & 0x04):
                ph["flags"]["names"].append("PF_R")

            ph["align"] = (
                self.buf.ru64l()
                if self.little else self.buf.ru64()) if self.wide else (
                    self.buf.ru32l() if self.little else self.buf.ru32())

            if meta["header"]["phentsize"] > (0x38 if self.wide else 0x20):
                self.buf.skip(meta["header"]["phentsize"] -
                              (0x38 if self.wide else 0x20))

            with self.buf:
                self.buf.seek(ph["offset"])
                with self.buf.sub(ph["filesz"]):
                    ph["blob"] = chew(self.buf, blob_mode=True)

            meta["program-headers"].append(ph)

        self.buf.seek(meta["header"]["shoff"])
        meta["section-headers"] = []
        for i in range(0, meta["header"]["shnum"]):
            sh = {}
            sh["name"] = {
                "offset": self.buf.ru32l() if self.little else self.buf.ru32()
            }
            sh["type"] = utils.unraw(
                self.buf.ru32l() if self.little else self.buf.ru32(), 4, {
                    0x00000000: "SHT_NULL",
                    0x00000001: "SHT_PROGBITS",
                    0x00000002: "SHT_SYMTAB",
                    0x00000003: "SHT_STRTAB",
                    0x00000004: "SHT_RELA",
                    0x00000005: "SHT_HASH",
                    0x00000006: "SHT_DYNAMIC",
                    0x00000007: "SHT_NOTE",
                    0x00000008: "SHT_NOBITS",
                    0x00000009: "SHT_REL",
                    0x0000000a: "SHT_SHLIB",
                    0x0000000b: "SHT_DYNSYM",
                    0x0000000e: "SHT_INIT_ARRAY",
                    0x0000000f: "SHT_FINI_ARRAY",
                    0x00000010: "SHT_PREINIT_ARRAY",
                    0x00000011: "SHT_GROUP",
                    0x00000012: "SHT_SYMTAB_SHNDX",
                    0x00000013: "SHT_NUM",
                    0x6ffffff5: "SHT_GNU_ATTRIBUTES",
                    0x6ffffff6: "SHT_GNU_HASH",
                    0x6ffffff7: "SHT_GNU_LIBLIST",
                    0x6ffffff8: "SHT_CHECKSUM",
                    0x6ffffffd: "SHT_GNU_verdef",
                    0x6ffffffe: "SHT_GNU_verneed",
                    0x6fffffff: "SHT_GNU_versym"
                })

            flags = (self.buf.ru64l()
                     if self.little else self.buf.ru64()) if self.wide else (
                         self.buf.ru32l() if self.little else self.buf.ru32())
            sh["flags"] = {"raw": flags, "names": []}

            if bool(flags & 0x0001):
                sh["flags"]["names"].append("SHF_WRITE")
            if bool(flags & 0x0002):
                sh["flags"]["names"].append("SHF_ALLOC")
            if bool(flags & 0x0004):
                sh["flags"]["names"].append("SHF_EXECINSTR")
            if bool(flags & 0x0010):
                sh["flags"]["names"].append("SHF_MERGE")
            if bool(flags & 0x0020):
                sh["flags"]["names"].append("SHF_STRINGS")
            if bool(flags & 0x0040):
                sh["flags"]["names"].append("SHF_INFO_LINK")
            if bool(flags & 0x0080):
                sh["flags"]["names"].append("SHF_LINK_ORDER")
            if bool(flags & 0x0100):
                sh["flags"]["names"].append("SHF_OS_NONCONFORMING")
            if bool(flags & 0x0200):
                sh["flags"]["names"].append("SHF_GROUP")
            if bool(flags & 0x0400):
                sh["flags"]["names"].append("SHF_TLS")

            sh["addr"] = self.hex((self.buf.ru64l(
            ) if self.little else self.buf.ru64()) if self.wide else (
                self.buf.ru32l() if self.little else self.buf.ru32()))
            sh["offset"] = (
                self.buf.ru64l()
                if self.little else self.buf.ru64()) if self.wide else (
                    self.buf.ru32l() if self.little else self.buf.ru32())
            sh["size"] = (self.buf.ru64l() if self.little else self.buf.ru64()
                          ) if self.wide else (self.buf.ru32l() if self.little
                                               else self.buf.ru32())
            sh["link"] = self.buf.ru32l() if self.little else self.buf.ru32()
            sh["info"] = self.buf.ru32l() if self.little else self.buf.ru32()
            sh["addralign"] = (
                self.buf.ru64l()
                if self.little else self.buf.ru64()) if self.wide else (
                    self.buf.ru32l() if self.little else self.buf.ru32())
            sh["entsize"] = (
                self.buf.ru64l()
                if self.little else self.buf.ru64()) if self.wide else (
                    self.buf.ru32l() if self.little else self.buf.ru32())

            with self.buf:
                self.buf.seek(sh["offset"])
                with self.buf.sub(sh["size"]):
                    sh["blob"] = chew(self.buf, blob_mode=True)

            if meta["header"]["shentsize"] > (0x40 if self.wide else 0x28):
                self.buf.skip(meta["header"]["shentsize"] -
                              (0x40 if self.wide else 0x28))

            meta["section-headers"].append(sh)

        if meta["header"]["shstrndx"] < len(meta["section-headers"]):
            section = meta["section-headers"][meta["header"]["shstrndx"]]
            if section["type"]["raw"] == 0x00000003:
                self.buf.seek(section["offset"])
                self.buf.pushunit()
                self.buf.setunit(section["size"])

                for section in meta["section-headers"]:
                    with self.buf:
                        self.buf.skip(section["name"]["offset"])
                        section["name"]["string"] = self.buf.rzs()

                self.buf.popunit()

        m = 0

        for ph in meta["program-headers"]:
            m = max(m, ph["offset"] + ph["filesz"])

        for sh in meta["section-headers"]:
            m = max(m, sh["offset"] + sh["size"])

            with self.buf:
                self.buf.seek(sh["offset"])
                with self.buf.sub(sh["size"]):
                    sh["parsed"] = {}

                    if sh["name"]["string"] in (".comment", ".interp"):
                        sh["parsed"]["string"] = self.buf.rs(
                            self.buf.available())
                    elif sh["name"]["string"].startswith(
                            ".note.") and self.buf.available() > 0:
                        base = self.buf.tell()
                        sh["parsed"]["namesz"] = self.buf.ru32l(
                        ) if self.little else self.buf.ru32()
                        sh["parsed"]["descsz"] = self.buf.ru32l(
                        ) if self.little else self.buf.ru32()
                        sh["parsed"]["type"] = self.buf.ru32l(
                        ) if self.little else self.buf.ru32()
                        sh["parsed"]["name"] = self.buf.rs(
                            sh["parsed"]["namesz"])

                        self.buf.skip((4 - sh["parsed"]["namesz"] % 4) if (
                            sh["parsed"]["namesz"] % 4 != 0) else 0)
                        self.buf.pushunit()
                        self.buf.setunit(sh["parsed"]["descsz"])

                        match sh["parsed"]["name"], sh["parsed"]["type"]:
                            case "GNU", 0x00000005:
                                sh["parsed"]["properties"] = []
                                while self.buf.unit > 0:
                                    prop = {}
                                    prop["type"] = utils.unraw(
                                        self.buf.ru32l()
                                        if self.little else self.buf.ru32(), 4,
                                        {0xc0008002: "X86_FEATURE_1_AND"})
                                    prop["datasz"] = self.buf.ru32l(
                                    ) if self.little else self.buf.ru32()

                                    self.buf.pushunit()
                                    self.buf.setunit(prop["datasz"])

                                    match prop["type"]["name"]:
                                        case "X86_FEATURE_1_AND":
                                            prop["data"] = {}
                                            prop["data"]["flags"] = {
                                                "raw":
                                                self.buf.ru32l() if self.little
                                                else self.buf.ru32(),
                                                "name": []
                                            }

                                            if prop["data"]["flags"][
                                                    "raw"] & 0x00000001:
                                                prop["data"]["flags"][
                                                    "name"].append("IBT")
                                            if prop["data"]["flags"][
                                                    "raw"] & 0x00000002:
                                                prop["data"]["flags"][
                                                    "name"].append("SHSTK")
                                        case "Unknown":
                                            prop["data"] = self.buf.rh(
                                                self.buf.unit)
                                            prop["unknown"] = True

                                    self.buf.skipunit()
                                    self.buf.popunit()

                                    self.buf.skip((
                                        8 - (self.buf.tell() - base) % 8) if (
                                            (self.buf.tell() - base) %
                                            8 != 0) else 0)

                                    sh["parsed"]["properties"].append(prop)
                            case _, _:
                                sh["parsed"]["desc"] = self.buf.rh(
                                    self.buf.unit)
                                sh["unknown"] = True

                        self.buf.popunit()
                    else:
                        del sh["parsed"]

        m = max(
            m, meta["header"]["phoff"] +
            meta["header"]["phnum"] * meta["header"]["phentsize"])
        m = max(
            m, meta["header"]["shoff"] +
            meta["header"]["shnum"] * meta["header"]["shentsize"])

        self.buf.seek(m)

        return meta


@module.register
class PeModule(module.RuminantModule):

    def identify(buf, ctx):
        return buf.peek(2) == b"MZ"

    def hex(self, val):
        return {
            "raw": val,
            "hex": "0x" + hex(val)[2:].zfill(16 if self.wide else 8)
        }

    def seek_vaddr(self, vaddr):
        for section in self.meta["sections"]:
            if vaddr >= section["vaddr"]["raw"] and vaddr < (
                    section["vaddr"]["raw"] + section["psize"]):
                self.buf.seek(section["paddr"])
                self.buf.pasunit(section["psize"])
                self.buf.skip(vaddr - section["vaddr"]["raw"])
                return

        raise ValueError(
            f"Cannot find section that maps {self.hex(vaddr)['hex']}")

    def chew(self):
        meta = {}
        meta["type"] = "pe"

        self.wide = False
        self.meta = meta

        self.buf.skip(2)
        meta["msdos-header"] = {}
        meta["msdos-header"]["stub"] = self.buf.rh(0x3a)
        meta["msdos-header"]["pe-header-offset"] = self.buf.ru32l()

        self.buf.seek(meta["msdos-header"]["pe-header-offset"])
        if self.buf.read(4) != b"PE\x00\x00":
            return meta

        meta["pe-header"] = {}
        meta["pe-header"]["machine"] = utils.unraw(self.buf.ru16l(), 2, {
            0x0000: "Unknown",
            0x014c: "i386",
            0x8664: "x64"
        })
        meta["pe-header"]["section-count"] = self.buf.ru16l()
        meta["pe-header"]["timestamp"] = datetime.datetime.fromtimestamp(
            self.buf.ru32l(), datetime.timezone.utc).isoformat()
        meta["pe-header"]["symbol-table-offset"] = self.buf.ru32l()
        meta["pe-header"]["symbol-count"] = self.buf.ru32l()
        meta["pe-header"]["optional-header-size"] = self.buf.ru16l()
        meta["pe-header"]["characteristics"] = {
            "raw": self.buf.ru16l(),
            "names": []
        }

        if meta["pe-header"]["characteristics"]["raw"] & 0x0001:
            meta["pe-header"]["characteristics"]["names"].append(
                "RELOCS_STRIPPED")
        if meta["pe-header"]["characteristics"]["raw"] & 0x0002:
            meta["pe-header"]["characteristics"]["names"].append(
                "EXECUTABLE_IMAGE")
        if meta["pe-header"]["characteristics"]["raw"] & 0x0004:
            meta["pe-header"]["characteristics"]["names"].append(
                "LINE_NUMS_STRIPPED")
        if meta["pe-header"]["characteristics"]["raw"] & 0x0008:
            meta["pe-header"]["characteristics"]["names"].append(
                "LOCAL_SYMS_STRIPPED")
        if meta["pe-header"]["characteristics"]["raw"] & 0x0010:
            meta["pe-header"]["characteristics"]["names"].append(
                "AGGRESSIVE_WS_TRIM")
        if meta["pe-header"]["characteristics"]["raw"] & 0x0020:
            meta["pe-header"]["characteristics"]["names"].append(
                "LARGE_ADDRESS_AWARE")
        if meta["pe-header"]["characteristics"]["raw"] & 0x0040:
            meta["pe-header"]["characteristics"]["names"].append("RESERVED")
        if meta["pe-header"]["characteristics"]["raw"] & 0x0080:
            meta["pe-header"]["characteristics"]["names"].append(
                "BYTES_REVERSED_LO")
        if meta["pe-header"]["characteristics"]["raw"] & 0x0100:
            meta["pe-header"]["characteristics"]["names"].append(
                "32BIT_MACHINE")
        if meta["pe-header"]["characteristics"]["raw"] & 0x0200:
            meta["pe-header"]["characteristics"]["names"].append(
                "DEBUG_STRIPPED ")
        if meta["pe-header"]["characteristics"]["raw"] & 0x0400:
            meta["pe-header"]["characteristics"]["names"].append(
                "REMOVABLE_RUN_FROM_SWAP ")
        if meta["pe-header"]["characteristics"]["raw"] & 0x0800:
            meta["pe-header"]["characteristics"]["names"].append(
                "NET_RUN_FROM_SWAP ")
        if meta["pe-header"]["characteristics"]["raw"] & 0x1000:
            meta["pe-header"]["characteristics"]["names"].append("SYSTEM")
        if meta["pe-header"]["characteristics"]["raw"] & 0x2000:
            meta["pe-header"]["characteristics"]["names"].append("DLL")
        if meta["pe-header"]["characteristics"]["raw"] & 0x4000:
            meta["pe-header"]["characteristics"]["names"].append(
                "UP_SYSTEM_ONLY")
        if meta["pe-header"]["characteristics"]["raw"] & 0x8000:
            meta["pe-header"]["characteristics"]["names"].append(
                "BYTES_REVERSED_HI")

        if meta["pe-header"]["optional-header-size"] > 0:
            meta["optional-header"] = {}

            typ = self.buf.ru16l()
            match typ:
                case 0x010b:
                    meta["optional-header"]["type"] = "PE32"
                    self.plus = False
                case 0x020b:
                    meta["optional-header"]["type"] = "PE32+"
                    self.plus = True
                case _:
                    meta["optional-header"][
                        "type"] = f"Unknown (0x{hex(typ)[2:].zfill(4)})"
                    meta["optional-header"]["unknown"] = True

            self.buf.pushunit()
            self.buf.setunit(meta["pe-header"]["optional-header-size"] - 2)

            if "unknown" not in meta["optional-header"]:
                meta["optional-header"]["major-linker-version"] = self.buf.ru8(
                )
                meta["optional-header"]["minor-linker-version"] = self.buf.ru8(
                )
                meta["optional-header"]["size-of-code"] = self.buf.ru32l()
                meta["optional-header"][
                    "size-of-initialized-data"] = self.buf.ru32l()
                meta["optional-header"][
                    "size-of-uninitialized-data"] = self.buf.ru32l()
                meta["optional-header"]["address-of-entrypoint"] = self.hex(
                    self.buf.ru32l())
                meta["optional-header"]["base-of-code"] = self.hex(
                    self.buf.ru32l())

                if not self.plus:
                    meta["optional-header"]["base-of-data"] = self.hex(
                        self.buf.ru32l())

                self.wide = self.plus

                if self.buf.available() > 0:
                    meta["optional-header"]["image-base"] = self.hex(
                        self.buf.ru64l() if self.wide else self.buf.ru32l())
                    meta["optional-header"][
                        "section-alignment"] = self.buf.ru32l()
                    meta["optional-header"]["file-alignment"] = self.buf.ru32l(
                    )
                    meta["optional-header"][
                        "major-os-version"] = self.buf.ru16l()
                    meta["optional-header"][
                        "minor-os-version"] = self.buf.ru16l()
                    meta["optional-header"][
                        "major-image-version"] = self.buf.ru16l()
                    meta["optional-header"][
                        "minor-image-version"] = self.buf.ru16l()
                    meta["optional-header"][
                        "major-subsystem-version"] = self.buf.ru16l()
                    meta["optional-header"][
                        "minor-subsystem-version"] = self.buf.ru16l()
                    meta["optional-header"]["win32-version"] = self.buf.ru32l()
                    meta["optional-header"]["size-of-image"] = self.buf.ru32l()
                    meta["optional-header"][
                        "size-of-headers"] = self.buf.ru32l()
                    meta["optional-header"]["checksum"] = self.buf.ru32l()
                    meta["optional-header"]["subsystem"] = utils.unraw(
                        self.buf.ru16l(), 2, {
                            0x0000: "UNKNOWN",
                            0x0001: "NATIVE",
                            0x0002: "WINDOWS_GUI",
                            0x0003: "WINDOWS_CUI",
                            0x0005: "OS2_CUI",
                            0x0007: "POSIX_CUI",
                            0x0008: "NATIVE_WINDOWS",
                            0x0009: "WINDOWS_CE_GUI",
                            0x000a: "EFI_APPLICATION",
                            0x000b: "EFI_BOOT_DEVICE_DRIVER",
                            0x000c: "EFI_RUNTIME_DRIVER",
                            0x000d: "EFI_ROM",
                            0x000e: "XBOX",
                            0x0010: "WINDOWS_BOOT_APPLICATION"
                        })
                    meta["optional-header"]["dll-characteristics"] = {
                        "raw": self.buf.ru16l(),
                        "names": []
                    }
                    if meta["optional-header"]["dll-characteristics"][
                            "raw"] & 0x0020:
                        meta["optional-header"]["dll-characteristics"][
                            "names"].append("HIGH_ENTROPY_VA")
                    if meta["optional-header"]["dll-characteristics"][
                            "raw"] & 0x0040:
                        meta["optional-header"]["dll-characteristics"][
                            "names"].append("DYNAMIC_BASE")
                    if meta["optional-header"]["dll-characteristics"][
                            "raw"] & 0x0080:
                        meta["optional-header"]["dll-characteristics"][
                            "names"].append("FORCE_INTEGRITY")
                    if meta["optional-header"]["dll-characteristics"][
                            "raw"] & 0x0100:
                        meta["optional-header"]["dll-characteristics"][
                            "names"].append("NX_COMPAT")
                    if meta["optional-header"]["dll-characteristics"][
                            "raw"] & 0x0200:
                        meta["optional-header"]["dll-characteristics"][
                            "names"].append("NO_ISOLATION")
                    if meta["optional-header"]["dll-characteristics"][
                            "raw"] & 0x0400:
                        meta["optional-header"]["dll-characteristics"][
                            "names"].append("NO_SEH")
                    if meta["optional-header"]["dll-characteristics"][
                            "raw"] & 0x0800:
                        meta["optional-header"]["dll-characteristics"][
                            "names"].append("NO_BIND")
                    if meta["optional-header"]["dll-characteristics"][
                            "raw"] & 0x1000:
                        meta["optional-header"]["dll-characteristics"][
                            "names"].append("APPCONTAINER")
                    if meta["optional-header"]["dll-characteristics"][
                            "raw"] & 0x2000:
                        meta["optional-header"]["dll-characteristics"][
                            "names"].append("WDM_DRIVER")
                    if meta["optional-header"]["dll-characteristics"][
                            "raw"] & 0x4000:
                        meta["optional-header"]["dll-characteristics"][
                            "names"].append("GUARD_CF")
                    if meta["optional-header"]["dll-characteristics"][
                            "raw"] & 0x8000:
                        meta["optional-header"]["dll-characteristics"][
                            "names"].append("TERMINAL_SERVER_AWARE")
                    meta["optional-header"][
                        "size-of-stack-reserve"] = self.buf.ru64l(
                        ) if self.plus else self.buf.ru32l()
                    meta["optional-header"][
                        "size-of-stack-commit"] = self.buf.ru64l(
                        ) if self.plus else self.buf.ru32l()
                    meta["optional-header"][
                        "size-of-heap-reserve"] = self.buf.ru64l(
                        ) if self.plus else self.buf.ru32l()
                    meta["optional-header"][
                        "size-of-heap-commit"] = self.buf.ru64l(
                        ) if self.plus else self.buf.ru32l()
                    meta["optional-header"]["loader-flags"] = self.buf.ru32l()

                    meta["optional-header"][
                        "number-of-rva-and-sizes"] = self.buf.ru32l()
                    meta["optional-header"]["rvas"] = []
                    for i in range(
                            0, meta["optional-header"]
                        ["number-of-rva-and-sizes"]):  # noqa: E131, E125
                        if self.buf.unit < 8:
                            break

                        rva = {}
                        rva["name"] = [
                            "Export Table", "Import Table", "Resource Table",
                            "Exception Table", "Certificate Table",
                            "Base Relocation Table", "Debug", "Architecture",
                            "Global Ptr", "TLS Table", "Load Config Table",
                            "Bound Import", "IAT", "Delay Import Descriptor",
                            "CLR Runtime Header", "Reserved"
                        ][i]
                        rva["base"] = self.buf.ru32l()
                        rva["size"] = self.buf.ru32l()

                        meta["optional-header"]["rvas"].append(rva)

            self.buf.skipunit()
            self.buf.popunit()

            meta["sections"] = []
            for i in range(0, meta["pe-header"]["section-count"]):
                section = {}
                section["name"] = self.buf.rs(8)
                section["vsize"] = self.buf.ru32l()
                section["vaddr"] = self.hex(self.buf.ru32l())
                section["psize"] = self.buf.ru32l()
                section["paddr"] = self.buf.ru32l()
                section["relocs-paddr"] = self.buf.ru32l()
                section["linenums-paddr"] = self.buf.ru32l()
                section["relocs-count"] = self.buf.ru16l()
                section["linenums-count"] = self.buf.ru16l()
                section["characteristics"] = {
                    "raw": self.buf.ru32l(),
                    "names": []
                }

                if section["characteristics"]["raw"] & 0x00000008:
                    section["characteristics"]["names"].append(
                        "SCN_TYPE_NO_PAD")
                if section["characteristics"]["raw"] & 0x00000020:
                    section["characteristics"]["names"].append("SCN_CNT_CODE")
                if section["characteristics"]["raw"] & 0x00000040:
                    section["characteristics"]["names"].append(
                        "SCN_CNT_INITIALIZED_DATA")
                if section["characteristics"]["raw"] & 0x00000080:
                    section["characteristics"]["names"].append(
                        "SCN_CNT_UNINITIALIZED_DATA")
                if section["characteristics"]["raw"] & 0x00000100:
                    section["characteristics"]["names"].append("SCN_LNK_OTHER")
                if section["characteristics"]["raw"] & 0x00000200:
                    section["characteristics"]["names"].append("SCN_LNK_INFO")
                if section["characteristics"]["raw"] & 0x00000800:
                    section["characteristics"]["names"].append(
                        "SCN_LNK_REMOVE")
                if section["characteristics"]["raw"] & 0x00001000:
                    section["characteristics"]["names"].append(
                        "SCN_LNK_COMDAT")
                if section["characteristics"]["raw"] & 0x00008000:
                    section["characteristics"]["names"].append("SCN_GPREL")
                if section["characteristics"]["raw"] & 0x00020000:
                    section["characteristics"]["names"].append(
                        "SCN_MEM_PURGEABLE")
                if section["characteristics"]["raw"] & 0x00020000:
                    section["characteristics"]["names"].append("SCN_MEM_16BIT")
                if section["characteristics"]["raw"] & 0x00040000:
                    section["characteristics"]["names"].append(
                        "SCN_MEM_LOCKED")
                if section["characteristics"]["raw"] & 0x00080000:
                    section["characteristics"]["names"].append(
                        "SCN_MEM_PRELOAD")
                if section["characteristics"]["raw"] & 0x00100000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_1BYTES")
                if section["characteristics"]["raw"] & 0x00200000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_2BYTES")
                if section["characteristics"]["raw"] & 0x00300000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_4BYTES")
                if section["characteristics"]["raw"] & 0x00400000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_8BYTES")
                if section["characteristics"]["raw"] & 0x00500000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_16BYTES")
                if section["characteristics"]["raw"] & 0x00600000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_32BYTES")
                if section["characteristics"]["raw"] & 0x00700000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_64BYTES")
                if section["characteristics"]["raw"] & 0x00800000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_128BYTES")
                if section["characteristics"]["raw"] & 0x00900000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_256BYTES")
                if section["characteristics"]["raw"] & 0x00A00000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_512BYTES")
                if section["characteristics"]["raw"] & 0x00B00000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_1024BYTES")
                if section["characteristics"]["raw"] & 0x00C00000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_2048BYTES")
                if section["characteristics"]["raw"] & 0x00D00000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_4096BYTES")
                if section["characteristics"]["raw"] & 0x00E00000:
                    section["characteristics"]["names"].append(
                        "SCN_ALIGN_8192BYTES")
                if section["characteristics"]["raw"] & 0x01000000:
                    section["characteristics"]["names"].append(
                        "SCN_LNK_NRELOC_OVFL")
                if section["characteristics"]["raw"] & 0x02000000:
                    section["characteristics"]["names"].append(
                        "SCN_MEM_DISCARDABLE")
                if section["characteristics"]["raw"] & 0x04000000:
                    section["characteristics"]["names"].append(
                        "SCN_MEM_NOT_CACHED")
                if section["characteristics"]["raw"] & 0x08000000:
                    section["characteristics"]["names"].append(
                        "SCN_MEM_NOT_PAGED")
                if section["characteristics"]["raw"] & 0x10000000:
                    section["characteristics"]["names"].append(
                        "SCN_MEM_SHARED")
                if section["characteristics"]["raw"] & 0x20000000:
                    section["characteristics"]["names"].append(
                        "SCN_MEM_EXECUTE")
                if section["characteristics"]["raw"] & 0x40000000:
                    section["characteristics"]["names"].append("SCN_MEM_READ")
                if section["characteristics"]["raw"] & 0x80000000:
                    section["characteristics"]["names"].append("SCN_MEM_WRITE")

                meta["sections"].append(section)

        m = self.buf.tell()

        if "optional-header" in meta:
            for rva in meta["optional-header"]["rvas"]:
                if rva["size"] == 0:
                    continue

                match rva["name"]:
                    case "Certificate Table":
                        self.buf.seek(rva["base"])
                        self.buf.pasunit(rva["size"])

                        rva["parsed"] = {}
                        rva["parsed"]["entries"] = []
                        while self.buf.unit > 0:
                            entry = {}
                            entry["length"] = self.buf.ru32l()
                            self.buf.pasunit(entry["length"])
                            rev = self.buf.ru16l()
                            entry["revision"] = f"{rev >> 8}.{rev & 0xff}"
                            entry["type"] = utils.unraw(
                                self.buf.ru16l(), 2, {
                                    0x0001: "X509",
                                    0x0002: "PKCS_SIGNED_DATA"
                                })
                            entry["blob"] = chew(self.buf.peek(self.buf.unit),
                                                 blob_mode=True)
                            entry["signature"] = utils.read_der(self.buf)

                            self.buf.sapunit()
                            if self.buf.unit >= 8 and entry["length"] % 8 != 0:
                                self.buf.skip(8 - (entry["length"] % 8))

                            rva["parsed"]["entries"].append(entry)

                        self.buf.sapunit()
                    case "CLR Runtime Header":
                        self.seek_vaddr(rva["base"])
                        self.buf.setunit(min(self.buf.unit, rva["size"]))

                        rva["parsed"] = {}
                        rva["parsed"]["size"] = self.buf.ru32l()
                        self.buf.setunit(min(self.buf.unit, rva["size"] - 2))
                        rva["parsed"][
                            "major-runtime-version"] = self.buf.ru16l()
                        rva["parsed"][
                            "minor-runtime-version"] = self.buf.ru16l()
                        rva["parsed"]["metadata"] = {
                            "base": self.hex(self.buf.ru32l()),
                            "size": self.hex(self.buf.ru32l())
                        }
                        rva["parsed"]["flags"] = self.buf.ru32l()
                        rva["parsed"]["entry"] = self.hex(self.buf.ru32l())
                        rva["parsed"]["resources"] = {
                            "base": self.hex(self.buf.ru32l()),
                            "size": self.hex(self.buf.ru32l())
                        }
                        rva["parsed"]["code-manager-table"] = {
                            "base": self.hex(self.buf.ru32l()),
                            "size": self.hex(self.buf.ru32l())
                        }
                        rva["parsed"]["vtable-fixups"] = {
                            "base": self.hex(self.buf.ru32l()),
                            "size": self.hex(self.buf.ru32l())
                        }
                        rva["parsed"]["export-address-table-jumps"] = {
                            "base": self.hex(self.buf.ru32l()),
                            "size": self.hex(self.buf.ru32l())
                        }
                        rva["parsed"]["managed-native-header"] = {
                            "base": self.hex(self.buf.ru32l()),
                            "size": self.hex(self.buf.ru32l())
                        }

                        self.buf.sapunit()

        m = self.buf.tell()
        for section in meta["sections"]:
            m = max(m, section["paddr"] + section["psize"])

        self.buf.seek(m)

        return meta


@module.register
class NbtModule(module.RuminantModule):

    def identify(buf, ctx):
        return (not ctx["walk"]) and (buf.pu32() & 0xffffffc0 == 0x0a000000)

    def chew(self):
        meta = {}
        meta["type"] = "nbt"

        meta["data"] = {}
        while self.buf.available() > 0:
            key, value = utils.read_nbt(self.buf)
            meta["data"][key] = value

        return meta


@module.register
class McaModule(module.RuminantModule):
    priority = 1

    def identify(buf, ctx):
        if ctx["walk"]:
            return False

        try:
            with buf:
                if buf.available() < 0x2000:
                    return False

                found_chunk = False
                for i in range(0, 1024):
                    offset = buf.ru32()
                    length = (offset & 0xff) * 0x1000
                    offset = (offset >> 8) * 0x1000

                    if offset < 2 and length != 0:
                        return False

                    if length == 0:
                        continue

                    found_chunk = True

                    with buf:
                        buf.seek(offset)
                        length2 = buf.ru32()
                        if length2 > length:
                            return False

                        if buf.ru8() not in (0x01, 0x02, 0x03, 0x04, 0x7f):
                            return False

                    return found_chunk
        except Exception:
            return False

    def chew(self):
        meta = {}
        meta["type"] = "mca"

        meta["chunk-count"] = 0
        meta["chunks"] = {}
        for i in range(0, 1024):
            offset = self.buf.ru32()
            length = (offset & 0xff) * 0x1000
            offset = (offset >> 8) * 0x1000

            if length != 0:
                meta["chunk-count"] += 1
                chunk = {}
                meta["chunks"][f"({i % 32}, {i // 32})"] = chunk

                chunk["offset"] = offset
                chunk["padded-length"] = length
                chunk["length"] = 0

                with self.buf:
                    self.buf.seek(0x1000 + i * 4)
                    chunk["timestamp"] = datetime.datetime.fromtimestamp(
                        self.buf.ru32(), datetime.timezone.utc).isoformat()

                    self.buf.seek(offset)
                    chunk["length"] = self.buf.ru32()
                    self.buf.pasunit(chunk["length"])

                    chunk["compression"] = utils.unraw(self.buf.ru8(), 1, {
                        0x01: "GZip",
                        0x02: "zlib",
                        0x03: "Uncompressed"
                    })

                    data = None
                    content = self.buf.readunit()
                    match chunk["compression"]["raw"]:
                        case 0x01:
                            data = gzip.decompress(content)
                        case 0x02:
                            data = zlib.decompress(content)
                        case 0x03:
                            data = content
                        case _:
                            chunk["unknown"] = True

                    if data is not None:
                        chunk["data"] = chew(data)

                    self.buf.sapunit()

        m = 0x2000
        for chunk in meta["chunks"].values():
            m = max(m, chunk["offset"] + chunk["padded-length"])

        self.buf.seek(m)

        return meta

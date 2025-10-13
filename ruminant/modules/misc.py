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

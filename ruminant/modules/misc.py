from .. import module, utils, constants
from ..buf import Buf
from . import chew
import tempfile
import sqlite3
import datetime
import gzip
import zlib
import time
import binascii
import base64


@module.register
class WasmModule(module.RuminantModule):
    desc = "WASM module files."

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
    desc = "BitTorrent files."

    def identify(buf, ctx):
        with buf:
            try:
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
            except Exception:
                return False

    def chew(self):
        meta = {}
        meta["type"] = "magnet"

        meta["data"] = utils.read_bencode(self.buf)

        return meta


@module.register
class Sqlite3Module(module.RuminantModule):
    desc = "sqlite3 database files."

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
    desc = "Java class files including a disassembler."

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

    def sign(self, i):
        if i >= 0:
            return "+" + str(i)
        else:
            return str(i)

    def read_element(self):
        tag = self.buf.read(1)
        match tag:
            case b"B" | b"C" | b"D" | b"F" | b"I" | b"J" | b"S" | b"Z" | b"s" | b"c":
                return self.resolve(self.buf.ru16())
            case b"[":
                return [self.read_element() for i in range(0, self.buf.ru16())]
            case b"e":
                typ = self.resolve(self.buf.ru16())
                return typ + self.resolve(self.buf.ru16())
            case b"@":
                return self.read_annotation()
            case _:
                raise ValueError(f"Unkown tag type '{tag.decode('latin-1')}'")

    def read_annotation(self, val=None):
        if val is None:
            val = {}

        val["type"] = self.resolve(self.buf.ru16())

        val["values"] = []
        for i in range(0, self.buf.ru16()):
            pair = {}
            pair["key"] = self.resolve(self.buf.ru16())
            pair["value"] = self.read_element()

            val["values"].append(pair)

        return val

    def read_type_annotation(self):
        # https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html#jvms-4.7.20

        val = {}
        val["data"] = {}

        tag = self.buf.read(1)
        match tag:
            case b"\x11" | b"\x12":
                val["data"]["type-parameter-index"] = self.buf.ru8()
                val["data"]["bound-index"] = self.buf.ru8()
            case b"\x13" | b"\x14" | b"\x15":
                pass
            case b"\x16":
                val["data"]["formal-parameter-index"] = self.buf.ru8()
            case b"\x40":
                val["data"]["table"] = [{
                    "start-pc": self.buf.ru16(),
                    "length": self.buf.ru16(),
                    "index": self.buf.ru16()
                } for i in range(0, self.buf.ru16())]
            case b"\x43" | b"\x44" | b"\x45" | b"\x46":
                val["data"]["offset"] = self.buf.ru16()
            case _:
                raise ValueError(f"Unkown tag type '{tag.decode('latin-1')}'")

        val["type-path"] = [[self.buf.ru8(), self.buf.ru8()]
                            for i in range(0, self.buf.ru8())]
        self.read_annotation(val)

        return val

    def read_verification_type(self):
        tag = self.buf.ru8()
        match tag:
            case 0x00:
                return "Top"
            case 0x01:
                return "Integer"
            case 0x02:
                return "Float"
            case 0x05:
                return "Null"
            case 0x06:
                return "UninitializedThis"
            case 0x07:
                return ("Object", self.resolve(self.buf.ru16()))
            case 0x08:
                return ("Uninitialized", self.buf.ru16())
            case 0x04:
                return "Long"
            case 0x03:
                return "Double"
            case _:
                raise ValueError(f"Unknown stack verification type '{tag}'")

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
                                    self.sign(self.buf.ri16(
                                    ) if wide else self.buf.ri8())
                                ]
                            case 0x10 | 0xbc:
                                name = [name, self.sign(self.buf.ri8())]
                            case 0x11 | 0x99 | 0x9a | 0x9b | 0x9c | 0x9d | 0x9e | 0x9f | 0xa0 | 0xa1 | 0xa2 | 0xa3 | 0xa4 | 0xa5 | 0xa6 | 0xa7 | 0xa8 | 0xc6 | 0xc7:
                                name = [name, self.sign(self.buf.ri16())]
                            case 0x13 | 0x14 | 0xb2 | 0xb3 | 0xb4 | 0xb5 | 0xb6 | 0xb7 | 0xb8 | 0xbb | 0xbd | 0xc0 | 0xc1:
                                name = [name, self.buf.ru16()]
                            case 0xc8 | 0xc9:
                                name = [name, self.sign(self.buf.ri32())]
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
                                    self.sign(self.buf.ri16(
                                    ) if wide else self.buf.ri8())
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
                case "LocalVariableTypeTable":
                    val = []
                    for i in range(0, self.buf.ru16()):
                        val.append({
                            "start-pc": self.buf.ru16(),
                            "length": self.buf.ru16(),
                            "name": self.resolve(self.buf.ru16()),
                            "signature": self.resolve(self.buf.ru16()),
                            "index": self.buf.ru16()
                        })
                case "MethodParameters":
                    val = []
                    for i in range(0, self.buf.ru8()):
                        param = {}
                        param["name"] = self.resolve(self.buf.ru16())
                        param["access-flags"] = utils.unpack_flags(
                            self.buf.ru16(), ((4, "final"), (12, "synthetic"),
                                              (15, "mandated")))

                        val.append(param)
                case "StackMapTable":
                    val = []
                    for i in range(0, self.buf.ru16()):
                        tag = self.buf.ru8()
                        if tag <= 63:
                            val.append({
                                "type": "same",
                                "offset-delta": tag - 64
                            })
                        elif tag <= 127:
                            val.append({
                                "type": "same-locals-1-stack-item",
                                "offset-delta": tag - 64,
                                "stack": self.read_verification_type()
                            })
                        elif tag == 247:
                            val.append({
                                "type": "same-locals-1-stack-item-extended",
                                "offset-delta": self.buf.ru16(),
                                "stack": self.read_verification_type()
                            })
                        elif tag >= 248 and tag <= 250:
                            val.append({
                                "type": "CHOP",
                                "offset-delta": self.buf.ru16()
                            })
                        elif tag == 251:
                            val.append({
                                "type": "same-frame-extended",
                                "offset-delta": self.buf.ru16(),
                            })
                        elif tag >= 252 and tag <= 254:
                            val.append({
                                "type":
                                "same-frame-extended",
                                "offset-delta":
                                self.buf.ru16(),
                                "locals": [
                                    self.read_verification_type()
                                    for i in range(0, tag - 251)
                                ]
                            })
                        elif tag == 255:
                            frame = {}
                            frame["type"] = "full"
                            frame["offset-delta"] = self.buf.ru16()
                            frame["locals"] = [
                                self.read_verification_type()
                                for i in range(0, self.buf.ru16())
                            ]
                            frame["stack"] = [
                                self.read_verification_type()
                                for i in range(0, self.buf.ru16())
                            ]

                            val.append(frame)
                        else:
                            raise ValueError(
                                f"Unknown stack frame type '{tag}'")
                case "InnerClasses":
                    val = []
                    for i in range(0, self.buf.ru16()):
                        clazz = {}
                        clazz["inner-info"] = self.resolve(self.buf.ru16())
                        clazz["outer-info"] = self.resolve(self.buf.ru16())
                        clazz["inner-name"] = self.resolve(self.buf.ru16())
                        clazz["access-flags"] = utils.unpack_flags(
                            self.buf.ru16(),
                            ((0, "public"), (1, "private"), (2, "protected"),
                             (3, "static"), (4, "final"), (9, "interface"),
                             (10, "abstract"), (12, "synthetic"),
                             (13, "annotation"), (14, "enum")))
                        val.append(clazz)
                case "Record":
                    val = []
                    for i in range(0, self.buf.ru16()):
                        comp = {}
                        comp["name"] = self.resolve(self.buf.ru16())
                        comp["descriptor"] = self.resolve(self.buf.ru16())
                        self.read_attributes(comp)
                        val.append(comp)
                case "BootstrapMethods":
                    val = []
                    for i in range(0, self.buf.ru16()):
                        bmth = {}
                        bmth["method"] = self.resolve(self.buf.ru16())

                        bmth["arguments"] = []
                        for i in range(0, self.buf.ru16()):
                            bmth["arguments"].append(
                                self.resolve(self.buf.ru16()))

                        val.append(bmth)
                case "EnclosingMethod":
                    val = {
                        "class": self.resolve(self.buf.ru16()),
                        "method": self.resolve(self.buf.ru16())
                    }
                case "Deprecated":
                    val = True
                case "RuntimeVisibleAnnotations" | "RuntimeInvisibleAnnotations":
                    val = []
                    for i in range(0, self.buf.ru16()):
                        val.append(self.read_annotation())
                case "RuntimeVisibleTypeAnnotations" | "RuntimeInvisibleTypeAnnotations":
                    val = []
                    for i in range(0, self.buf.ru16()):
                        val.append(self.read_type_annotation())
                case "RuntimeVisibleParameterAnnotations" | "RuntimeInvisibleParameterAnnotations":
                    val = []
                    for i in range(0, self.buf.ru8()):
                        val2 = []
                        for i in range(0, self.buf.ru16()):
                            val2.append(self.read_annotation())

                        val.append(val2)
                case "NestHost" | "ConstantValue":
                    val = self.resolve(self.buf.ru16())
                case "NestMembers" | "Exceptions" | "PermittedSubclasses":
                    val = []
                    for i in range(0, self.buf.ru16()):
                        val.append(self.resolve(self.buf.ru16()))
                case "SourceFile" | "Signature":
                    val = self.resolve(self.buf.ru16())
                case _:
                    val = {
                        "payload": self.buf.rh(self.buf.unit),
                        "unknown": True
                    }

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
                    const = ["class-ref", self.buf.ru16()]
                case 8:
                    const = ["string-ref", self.buf.ru16()]
                case 9:
                    const = ["field-ref", self.buf.ru16(), self.buf.ru16()]
                case 10:
                    const = ["method-ref", self.buf.ru16(), self.buf.ru16()]
                case 11:
                    const = [
                        "interface-method-ref",
                        self.buf.ru16(),
                        self.buf.ru16()
                    ]
                case 12:
                    const = ["name-and-type", self.buf.ru16(), self.buf.ru16()]
                case 15:
                    const = ["method-handle", -self.buf.ru8(), self.buf.ru16()]
                case 16:
                    const = ["method-type", self.buf.ru16()]
                case 18:
                    const = [
                        "invokedynamic", -self.buf.ru16(),
                        self.buf.ru16()
                    ]
                case _:
                    raise ValueError(f"Unknown constant type {tag}")

            meta["constants"][i if not skip else i + 1] = const

        done = False
        while not done:
            done = True
            for k, v in meta["constants"].items():
                if isinstance(v, list):
                    done = False

                    full = True
                    for i in range(1, len(v)):
                        if isinstance(v[i], int):
                            if v[0] == "method-handle" and v[i] < 0:
                                v[i] = {
                                    1: "REF_getField",
                                    2: "REF_getStatic",
                                    3: "REF_putField",
                                    4: "REF_putStatic",
                                    5: "REF_invokeVirtual",
                                    6: "REF_invokeStatic",
                                    7: "REF_invokeSpecial",
                                    8: "REF_newInvokeSpecial",
                                    9: "REF_invokeInterface"
                                }.get(-v[i])
                            elif v[0] == "invokedynamic" and v[i] < 0:
                                v[i] = f"#{-v[i]}"
                            else:
                                if isinstance(self.resolve(v[i]), str):
                                    v[i] = self.resolve(v[i])
                                elif self.resolve(v[i]) is None:
                                    v[i] = "null"
                                else:
                                    full = False

                    if full:
                        match v[0]:
                            case "class-ref":
                                meta["constants"][k] = f"L{v[1]};"
                            case "method-ref" | "field-ref":
                                meta["constants"][k] = f"{v[1]}{v[2]}"
                            case "name-and-type":
                                meta["constants"][k] = f"{v[1]}:{v[2]}"
                            case "string-ref":
                                meta["constants"][k] = repr(v[1])
                            case "method-handle" | "invokedynamic":
                                meta["constants"][k] = f"{v[1]} {v[2]}"
                            case "interface-method-ref":
                                meta["constants"][k] = f"{v[1]}.{v[2]}"
                            case "method-type":
                                meta["constants"][k] = v[1]
                            case _:
                                raise ValueError(
                                    f"Cannot render type '{v[0]}' in {v}")

        meta["access-flags"] = utils.unpack_flags(
            self.buf.ru16(), ((0, "public"), (4, "final"), (5, "super"),
                              (9, "interface"), (10, "abstract")))
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

            field["flags"] = utils.unpack_flags(
                self.buf.ru16(),
                ((0, "public"), (1, "private"), (2, "protected"),
                 (3, "static"), (4, "final"), (6, "volatile"),
                 (7, "transient"), (12, "synthetic"), (14, "enum")))
            field["name"] = self.resolve(self.buf.ru16())
            field["descriptor"] = self.resolve(self.buf.ru16())

            self.read_attributes(field)

            meta["fields"].append(field)

        meta["method-count"] = self.buf.ru16()
        meta["methods"] = []
        for i in range(0, meta["method-count"]):
            method = {}

            method["flags"] = utils.unpack_flags(
                self.buf.ru16(),
                ((0, "public"), (1, "private"), (2, "protected"),
                 (3, "static"), (4, "final"), (5, "synchronized"),
                 (6, "bridge"), (7, "varargs"), (8, "native"),
                 (10, "abstract"), (11, "strict"), (12, "synthetic")))
            method["name"] = self.resolve(self.buf.ru16())
            method["descriptor"] = self.resolve(self.buf.ru16())

            self.read_attributes(method)

            meta["methods"].append(method)

        self.read_attributes(meta)

        return meta


@module.register
class ElfModule(module.RuminantModule):
    desc = "ELF files."

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

            ph["flags"] = utils.unpack_flags(ph["flags"],
                                             ((0, "PF_X"), (1, "PF_W"),
                                              (2, "PF_R")))

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
            sh["flags"] = utils.unpack_flags(
                flags,
                ((0, "SHF_WRITE"), (1, "SHF_ALLOC"), (2, "SHF_EXECINSTR"),
                 (4, "SHF_MERGE"), (5, "SHF_STRINGS"), (6, "SHF_INFO_LINK"),
                 (7, "SHF_LINK_ORDER"), (8, "SHF_OS_NONCONFORMING"),
                 (9, "SHF_GROUP"), (10, "SHF_TLS")))

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

            if sh["type"]["name"] != "SHT_NOBITS":
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

        for sh in meta["section-headers"]:
            if sh["name"]["string"] == ".strtab":
                with self.buf:
                    self.buf.seek(sh["offset"])
                    self.namebuf = Buf(self.buf.read(sh["size"]))
        m = 0

        for ph in meta["program-headers"]:
            m = max(m, ph["offset"] + ph["filesz"])

        for sh in meta["section-headers"]:
            if sh["type"]["name"] == "SHT_NOBITS":
                continue

            m = max(m, sh["offset"] + sh["size"])

            with self.buf:
                self.buf.seek(sh["offset"])
                with self.buf.sub(sh["size"]):
                    sh["parsed"] = {}

                    if sh["name"]["string"] == ".interp":
                        sh["parsed"]["string"] = self.buf.rs(
                            self.buf.available())
                    elif sh["name"]["string"] == ".comment":
                        sh["parsed"]["strings"] = []
                        while self.buf.available() > 0:
                            sh["parsed"]["strings"].append(self.buf.rzs())
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
                    elif sh["name"]["string"] == ".symtab":
                        sh["parsed"]["symbols"] = []
                        while self.buf.available() > 0:
                            sym = {}
                            sym["name"] = {
                                "index":
                                self.buf.ru32l()
                                if self.little else self.buf.ru32()
                            }
                            self.namebuf.seek(sym["name"]["index"])
                            sym["name"]["string"] = self.namebuf.rzs()

                            if sym["name"]["string"].startswith("_Z"):
                                try:
                                    sym["name"]["demangled"] = utils.demangle(
                                        sym["name"]["string"])
                                except Exception:
                                    pass

                            if self.wide:
                                sym["info"] = self.buf.ru8()
                                sym["other"] = self.buf.ru8()
                                sym["section-index"] = self.buf.ru16l(
                                ) if self.little else self.buf.ru16()
                                sym["addr"] = hex(
                                    self.buf.ru64l() if self.little else self.
                                    buf.ru64())[2:].zfill(8)
                                sym["size"] = self.buf.ru64l(
                                ) if self.little else self.buf.ru64()
                            else:
                                sym["addr"] = hex(
                                    self.buf.ru32l() if self.little else self.
                                    buf.ru32())[2:].zfill(16)
                                sym["size"] = self.buf.ru32l(
                                ) if self.little else self.buf.ru32()
                                sym["info"] = self.buf.ru8()
                                sym["other"] = self.buf.ru8()
                                sym["section-index"] = self.buf.ru16l(
                                ) if self.little else self.buf.ru16()

                            sh["parsed"]["symbols"].append(sym)
                    elif sh["name"]["string"] == ".modinfo":
                        sh["parsed"]["entries"] = []
                        while self.buf.available() > 0:
                            sh["parsed"]["entries"].append(self.buf.rzs())
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
    desc = "PE files like EXE or EFI files."

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
        meta["pe-header"]["machine"] = utils.unraw(
            self.buf.ru16l(), 2, {
                0x0000: "Unknown",
                0x014c: "i386",
                0x8664: "x64",
                0xaa64: "ARM64 little endian"
            })
        meta["pe-header"]["section-count"] = self.buf.ru16l()
        meta["pe-header"]["timestamp"] = datetime.datetime.fromtimestamp(
            self.buf.ru32l(), datetime.timezone.utc).isoformat()
        meta["pe-header"]["symbol-table-offset"] = self.buf.ru32l()
        meta["pe-header"]["symbol-count"] = self.buf.ru32l()
        meta["pe-header"]["optional-header-size"] = self.buf.ru16l()

        meta["pe-header"]["characteristics"] = utils.unpack_flags(
            self.buf.ru16l(), (
                (0, "RELOCS_STRIPPED"),
                (1, "EXECUTABLE_IMAGE"),
                (2, "LINE_NUMS_STRIPPED"),
                (3, "LOCAL_SYMS_STRIPPED"),
                (4, "AGGRESSIVE_WS_TRIM"),
                (5, "LARGE_ADDRESS_AWARE"),
                (6, "RESERVED"),
                (7, "BYTES_REVERSED_LO"),
                (8, "32BIT_MACHINE"),
                (9, "DEBUG_STRIPPED"),
                (10, "REMOVABLE_RUN_FROM_SWAP"),
                (11, "NET_RUN_FROM_SWAP"),
                (12, "SYSTEM"),
                (13, "DLL"),
                (14, "UP_SYSTEM_ONLY"),
                (15, "BYTES_REVERSED_HI"),
            ))

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

            self.buf.pasunit(meta["pe-header"]["optional-header-size"] - 2)

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
                    meta["optional-header"][
                        "dll-characteristics"] = utils.unpack_flags(
                            self.buf.ru16l(), (
                                (5, "HIGH_ENTROPY_VA"),
                                (6, "DYNAMIC_BASE"),
                                (7, "FORCE_INTEGRITY"),
                                (8, "NX_COMPAT"),
                                (9, "NO_ISOLATION"),
                                (10, "NO_SEH"),
                                (11, "NO_BIND"),
                                (12, "APPCONTAINER"),
                                (13, "WDM_DRIVER"),
                                (14, "GUARD_CF"),
                                (15, "TERMINAL_SERVER_AWARE"),
                            ))
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

            self.buf.sapunit()

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
                section["characteristics"] = utils.unpack_flags(
                    self.buf.ru32l(), (
                        (3, "SCN_TYPE_NO_PAD"),
                        (5, "SCN_CNT_CODE"),
                        (6, "SCN_CNT_INITIALIZED_DATA"),
                        (7, "SCN_CNT_UNINITIALIZED_DATA"),
                        (8, "SCN_LNK_OTHER"),
                        (9, "SCN_LNK_INFO"),
                        (11, "SCN_LNK_REMOVE"),
                        (12, "SCN_LNK_COMDAT"),
                        (15, "SCN_GPREL"),
                        (17, "SCN_MEM_PURGEABLE"),
                        (18, "SCN_MEM_LOCKED"),
                        (19, "SCN_MEM_PRELOAD"),
                        (24, "SCN_LNK_NRELOC_OVFL"),
                        (25, "SCN_MEM_DISCARDABLE"),
                        (26, "SCN_MEM_NOT_CACHED"),
                        (27, "SCN_MEM_NOT_PAGED"),
                        (28, "SCN_MEM_SHARED"),
                        (29, "SCN_MEM_EXECUTE"),
                        (30, "SCN_MEM_READ"),
                        (31, "SCN_MEM_WRITE"),
                    ))

                if section["psize"] != 0:
                    with self.buf:
                        self.buf.seek(section["paddr"])

                        with self.buf.sub(section["psize"]):
                            section["blob"] = chew(
                                self.buf,
                                blob_mode=not (section["name"] == "mods" and
                                               self.buf.peek(4) == b"mimg"))

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
    desc = "Minecraft NBT files."

    def identify(buf, ctx):
        return (not ctx["walk"]) and (buf.pu32() & 0xffffffc0 == 0x0a000000)

    def clean(self, root):
        if isinstance(root, dict):
            for k, v in list(root.items()):
                if k in ("sections", "Heightmaps"):
                    root[k] = None
                else:
                    self.clean(v)
        elif isinstance(root, list):
            for elem in root:
                self.clean(elem)

    def parse(self, root):
        if isinstance(root, dict):
            for k, v in list(root.items()):
                if k == "icon" and isinstance(v, str) and len(v) > 100:
                    try:
                        root[k] = {
                            "raw": v,
                            "parsed": chew(base64.b64decode(v))
                        }
                    except binascii.Error:
                        pass
                else:
                    self.parse(v)
        elif isinstance(root, list):
            for elem in root:
                self.parse(elem)

    def chew(self):
        meta = {}
        meta["type"] = "nbt"

        meta["data"] = {}
        while self.buf.available() > 0:
            key, value = utils.read_nbt(self.buf)
            meta["data"][key] = value

        if self.extra_ctx.get("skip-chunk-data"):
            self.clean(meta["data"])

        self.parse(meta["data"])

        return meta


@module.register
class McaModule(module.RuminantModule):
    priority = 1
    desc = "Minecraft chunk region files."

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
                        chunk["data"] = chew(
                            data, extra_ctx={"skip-chunk-data": True})

                    self.buf.sapunit()

        m = 0x2000
        for chunk in meta["chunks"].values():
            m = max(m, chunk["offset"] + chunk["padded-length"])

        self.buf.seek(m)

        return meta


@module.register
class GrubModuleModule(module.RuminantModule):
    desc = "GRUB 2 module files."

    def identify(buf, ctx):
        return buf.peek(4) == b"mimg"

    def chew(self):
        meta = {}
        meta["type"] = "grub-module"

        self.buf.skip(4)
        meta["data"] = {}
        meta["data"]["padding"] = self.buf.ru32l()
        meta["data"]["offset"] = self.buf.ru64l()
        meta["data"]["size"] = self.buf.ru64l()
        meta["data"]["modules"] = []

        self.buf.pasunit(meta["data"]["size"] - 24)
        self.buf.skip(meta["data"]["offset"] - 24)

        while self.buf.unit > 0:
            module = {}
            module["type"] = utils.unraw(
                self.buf.ru32l(), 4, {
                    0x00000000: "ELF",
                    0x00000001: "MEMDISK",
                    0x00000002: "CONFIG",
                    0x00000003: "PREFIX",
                    0x00000004: "PUBKEY",
                    0x00000005: "DTB",
                    0x00000006: "DISABLE_SHIM_LOCK",
                })
            module["length"] = self.buf.ru32l()

            self.buf.pasunit(module["length"] - 8)

            match module["type"]["raw"]:
                case 0 | 1:
                    with self.buf.subunit():
                        module["data"] = chew(self.buf)
                case 3:
                    module["data"] = self.buf.rs(self.buf.unit)
                case _:
                    module["unknown"] = True
                    with self.buf.subunit():
                        module["data"] = chew(self.buf, blob_mode=True)

            self.buf.sapunit()

            meta["data"]["modules"].append(module)

        self.buf.sapunit()

        return meta


@module.register
class SpirVModule(module.RuminantModule):
    desc = "SPIR-V Vulkan shader files."

    def identify(buf, ctx):
        return buf.peek(4) in (b"\x07\x23\x02\x03", b"\x03\x02\x23\x07")

    def read(self):
        if self.little:
            return self.buf.ru32l()
        else:
            return self.buf.ru32()

    def read_rest(self, func=None):
        if func is None:
            func = self.read

        vals = []
        while self.buf.unit > 0:
            vals.append(func())

        return vals

    def read_string(self):
        s = b""
        while True:
            c = self.read()
            s += c.to_bytes(4, "little")
            if c & 0xff000000 == 0:
                break

        return utils.decode(s).rstrip("\x00")

    def read_memory_operands(self):
        val = utils.unpack_flags(
            self.read(),
            ((0, "Volatile"), (1, "Aligned"), (2, "Nontemporal"),
             (3, "MakePointerAvailable"), (4, "MakePointerVisible"),
             (5, "NonPrivatePointer"), (16, "AliasScopeINTELMask"),
             (17, "NoAliasINTELMask")))

        return val

    def chew(self):
        meta = {}
        meta["type"] = "spir-v"

        meta["header"] = {}
        self.little = self.buf.ru32l() == 0x07230203
        meta["header"]["endian"] = "little" if self.little else "big"
        ver = self.read()
        meta["header"]["version"] = f"{(ver >> 16) & 0xff}.{(ver >> 8) & 0xff}"
        ver = self.read()
        meta["header"]["generator"] = utils.unraw(
            ver >> 16, 2, {
                0x0000: "Khronos",
                0x0001: "LunarG",
                0x0002: "Valve",
                0x0003: "Codeplay",
                0x0004: "NVIDIA",
                0x0005: "ARM",
                0x0006: "Khronos - LLVM/SPIR-V Translator",
                0x0007: "Khronos - SPIR-V Tools Assembler",
                0x0008: "Khronos - Glslang Reference Front End",
                0x0009: "Qualcomm",
                0x000a: "AMD",
                0x000b: "Intel",
                0x000c: "Imagination",
                0x000d: "Google - Shaderc over Glslang",
                0x000e: "Google - spiregg",
                0x000f: "Google - rspirv",
                0x0010: "X-LEGEND - Mesa-IR/SPIR-V Translator",
                0x0011: "Khronos - SPIR-V Tools Linker",
                0x0012: "Wine - VKD3D Shader Compiler",
                0x0013: "Tellusim - Clay Shader Compiler",
                0x0014: "W3C WebGPU Group - WHLSL Shader Translator",
                0x0015: "Google - Clspv",
                0x0016: "LLVM - MLIR SPIR-V Serializer",
                0x0017: "Google - Tint Compiler",
                0x0018: "Google - ANGLE Shader Compiler",
                0x0019: "Netease Games - Messiah Shader Compiler",
                0x001a: "Xenia - Xenia Emulator Microcode Translator",
                0x001b: "Embark Studios - Rust GPU Compiler Backend",
                0x001c: "gfx-rs community - Naga",
                0x001d: "Mikkosoft Productions - MSP Shader Compiler",
                0x001e: "SpvGenTwo community - SpvGenTwo SPIR-V IR Tools",
                0x001f: "Google - Skia SkSL",
                0x0020: "TornadoVM - Beehive SPIRV Toolkit",
                0x0021: "DragonJoker - ShaderWriter",
                0x0022: "Rayan Hatout - SPIRVSmith",
                0x0023: "Saarland University - Shady",
                0x0024: "Taichi Graphics - Taichi",
                0x0025: "heroseh - Hero C Compiler",
                0x0026: "Meta - SparkSL",
                0x0027: "SirLynix - Nazara ShaderLang Compiler",
                0x0028: "Khronos - Slang Compiler",
                0x0029: "Zig Software Foundation - Zig Compiler",
                0x002a: "Rendong Liang - spq",
                0x002b: "LLVM - LLVM SPIR-V Backend",
                0x002c: "Robert Konrad - Kongruent",
                0x002d:
                "Kitsunebi Games - Nuvk SPIR-V Emitter and DLSL compiler",
                0x002e: "Nintendo",
                0x002f: "ARM",
                0x0030: "Goopax",
                0x0031: "Icyllis Milica - Arc3D Shader Compiler"
            })
        meta["header"]["generator-version"] = ver & 0xffff
        meta["header"]["bound"] = self.read()
        meta["header"]["reserved"] = self.read()

        meta["stream"] = []
        while self.buf.available():
            inst = {}
            opcode = self.read()
            inst["opcode"] = utils.unraw(opcode & 0xffff, 2,
                                         constants.SPIRV_OPCODES, True)
            inst["length"] = opcode >> 16

            self.buf.pasunit((inst["length"] - 1) * 4)

            inst["arguments"] = {}
            match inst["opcode"]:
                case "Capability":
                    inst["arguments"]["capability"] = utils.unraw(
                        self.read(), 4, constants.SPIRV_CAPABILITIES, True)
                case "ExtInstImport":
                    inst["arguments"]["result-id"] = self.read()
                    inst["arguments"]["name"] = self.read_string()
                case "MemoryModel":
                    inst["arguments"]["addressing-model"] = utils.unraw(
                        self.read(), 4, {
                            0x00000000: "Logical",
                            0x00000001: "Physical32",
                            0x00000002: "Physical64",
                            0x000014e4: "PhysicalStorageBuffer64"
                        }, True)

                    inst["arguments"]["memory-model"] = utils.unraw(
                        self.read(), 4, {
                            0x00000000: "Simple",
                            0x00000001: "GLSL450",
                            0x00000002: "OpenCL",
                            0x00000003: "Vulkan"
                        }, True)
                case "EntryPoint":
                    inst["arguments"]["execution-model"] = utils.unraw(
                        self.read(), 4, {
                            0x00000000: "Vertex",
                            0x00000001: "TessellationControl",
                            0x00000002: "TessellationEvaluation",
                            0x00000003: "Geometry",
                            0x00000004: "Fragment",
                            0x00000005: "GLCompute",
                            0x00000006: "Kernel",
                            0x00001493: "TaskNV",
                            0x00001494: "MeshNV",
                            0x000014c1: "RayGenerationKHR",
                            0x000014c2: "IntersectionKHR",
                            0x000014c3: "AnyHitKHR",
                            0x000014c4: "ClosestHitKHR",
                            0x000014c5: "MissKHR",
                            0x000014c6: "CallableKHR",
                            0x000014f4: "TaskEXT",
                            0x000014f5: "MeshEXT"
                        }, True)
                    inst["arguments"]["entry-point-id"] = self.read()
                    inst["arguments"]["name"] = self.read_string()
                    inst["arguments"]["interface-ids"] = self.read_rest()
                case "ExecutionMode":
                    inst["arguments"]["entry-point-id"] = self.read()
                    inst["arguments"]["execution-mode"] = utils.unraw(
                        self.read(), 4, constants.SPIRV_EXECUTION_MODES, True)
                    inst["arguments"]["strings"] = self.read_rest(
                        func=self.read_string)
                case "Source":
                    inst["arguments"]["source-language"] = utils.unraw(
                        self.read(), 4, {
                            0x00000000: "Unknown",
                            0x00000001: "ESSL",
                            0x00000002: "GLSL",
                            0x00000003: "OpenCL_C",
                            0x00000004: "OpenCL_CPP",
                            0x00000005: "HLSL",
                            0x00000006: "CPP_for_OpenCL",
                            0x00000007: "SYCL",
                            0x00000008: "HERO_C",
                            0x00000009: "NZSL",
                            0x0000000a: "WGSL",
                            0x0000000b: "Slang",
                            0x0000000c: "Zig",
                            0x0000000d: "Rust"
                        }, True)
                    inst["arguments"]["version"] = self.read()
                    if self.buf.unit > 0:
                        inst["arguments"]["file-id"] = self.read()
                    if self.buf.unit > 0:
                        inst["arguments"]["source"] = self.read_string()
                case "Name":
                    inst["arguments"]["target-id"] = self.read()
                    inst["arguments"]["name"] = self.read_string()
                case "Decorate":
                    inst["arguments"]["target-id"] = self.read()
                    inst["arguments"]["decoration"] = utils.unraw(
                        self.read(), 4, constants.SPIRV_DECORATIONS, True)

                    match inst["arguments"]["decoration"]:
                        case _:
                            inst["arguments"]["operands"] = self.read_rest()
                case "TypeVoid":
                    inst["arguments"]["result-id"] = self.read()
                case "TypeFunction":
                    inst["arguments"]["result-id"] = self.read()
                    inst["arguments"]["return-type-id"] = self.read()
                    inst["arguments"]["parameter-type-ids"] = self.read_rest()
                case "TypeVector":
                    inst["arguments"]["result-id"] = self.read()
                    inst["arguments"]["component-type-id"] = self.read()
                    inst["arguments"]["component-count"] = self.read()
                case "TypePointer":
                    inst["arguments"]["result-id"] = self.read()
                    inst["arguments"]["storage-class"] = utils.unraw(
                        self.read(), 4, constants.SPIRV_STORAGE_CLASSES, True)
                    inst["arguments"]["type-id"] = self.read()
                case "TypeFloat":
                    inst["arguments"]["result-id"] = self.read()
                    inst["arguments"]["width"] = self.read()
                case "Variable":
                    inst["arguments"]["result-type-id"] = self.read()
                    inst["arguments"]["result-id"] = self.read()
                    inst["arguments"]["storage-class"] = utils.unraw(
                        self.read(), 4, constants.SPIRV_STORAGE_CLASSES, True)
                    if self.buf.unit > 0:
                        inst["arguments"]["initializer-id"] = self.read()
                case "Function":
                    inst["arguments"]["result-type-id"] = self.read()
                    inst["arguments"]["result-id"] = self.read()
                    inst["arguments"]["function-control"] = utils.unpack_flags(
                        self.read(), (
                            (0, "Inline"),
                            (1, "DontInline"),
                            (2, "Pure"),
                            (3, "Const"),
                            (16, "OptNoneExt"),
                        ))

                    inst["arguments"]["function-type-id"] = self.read()
                case "Label":
                    inst["arguments"]["result-id"] = self.read()
                case "Load":
                    inst["arguments"]["result-type-id"] = self.read()
                    inst["arguments"]["result-id"] = self.read()
                    inst["arguments"]["pointer-id"] = self.read()
                    if self.buf.unit > 0:
                        inst["arguments"][
                            "pointer-id"] = self.read_memory_operands()
                case "Store":
                    inst["arguments"]["pointer-id"] = self.read()
                    inst["arguments"]["object-id"] = self.read()
                    if self.buf.unit > 0:
                        inst["arguments"][
                            "pointer-id"] = self.read_memory_operands()
                case "Return" | "FunctionEnd":
                    pass
                case _:
                    inst["arguments"]["raw"] = self.read_rest()
                    inst["unknown"] = True

            self.buf.sapunit()

            meta["stream"].append(inst)

        return meta


@module.register
class PycModule(module.RuminantModule):
    dev = True
    desc = "Python compiled bytecode files."

    def identify(buf, ctx):
        if buf.available() < 10:
            return False

        with buf:
            if buf.read(4)[2:] != b"\x0d\x0a":
                return False

            if buf.ru16():
                return True

            return buf.ru32() < int(time.time()) + (60 * 60 * 24 * 365 * 10)

    def chew(self):
        meta = {}
        meta["type"] = "pyc"

        meta["header"] = {}
        meta["header"]["magic"] = utils.unraw(self.buf.ru16l(), 2,
                                              constants.CPYTHON_MAGICS)
        self.buf.skip(2)
        meta["header"]["flags"] = self.buf.ru32l()
        if meta["header"]["flags"] & 0x0001:
            meta["header"]["source-hash"] = self.buf.rh(8)
        else:
            meta["header"]["timestamp"] = utils.unix_to_date(self.buf.ru32l())
            meta["header"]["source-length"] = self.buf.ru32l()

        meta["data"] = utils.read_marshal(self.buf,
                                          meta["header"]["magic"]["raw"])

        return meta


@module.register
class BlendModule(module.RuminantModule):
    desc = "Blender project files, currently kinda broken."

    def identify(buf, ctx):
        return buf.peek(7) == b"BLENDER"

    def r16(self):
        match self.mode:
            case "le32" | "le64":
                return self.buf.ru16l()
            case "be32" | "be64":
                return self.buf.ru16()

    def r32(self):
        match self.mode:
            case "le32" | "le64":
                return self.buf.ru32l()
            case "be32" | "be64":
                return self.buf.ru32()

    def rptr(self):
        match self.mode:
            case "le32":
                return self.buf.ru32l()
            case "le64":
                return self.buf.ru64l()
            case "be32":
                return self.buf.ru32()
            case "be64":
                return self.buf.ru64()

    def rptrh(self):
        return hex(self.rptr())[2:].zfill(8 if "32" in self.mode else 16)

    def chew(self):
        meta = {}
        meta["type"] = "blend"
        self.buf.skip(7)
        meta["mode"] = {
            "_v": "le32",
            "_V": "be32",
            "-v": "le64",
            "-V": "be64"
        }[self.buf.rs(2)]
        self.mode = meta["mode"]
        meta["version"] = int(self.buf.rs(3))

        meta["blocks"] = []
        while self.buf.available() > 0:
            block = {}
            block["type"] = self.buf.rs(4)
            block["size"] = self.r32()
            block["ptr"] = self.rptrh()
            block["sdna-index"] = self.r32()
            block["count"] = self.r32()

            self.buf.pasunit(block["size"])

            block["data"] = {}
            match block["type"]:
                case "DNA1":
                    self.buf.skip(4)
                    block["data"]["sections"] = []

                    with self.buf.subunit():
                        while self.buf.available() > 0:
                            section = {}
                            section["name"] = self.buf.rs(4)
                            section["data"] = {}

                            match section["name"]:
                                case "NAME" | "TYPE":
                                    section["data"]["count"] = self.r32()
                                    section["data"]["strings"] = [
                                        self.buf.rzs() for i in range(
                                            0, section["data"]["count"])
                                    ]
                                case "TLEN":
                                    count = 0
                                    for s in block["data"]["sections"]:
                                        if s["name"] == "TYPE":
                                            count = len(s["data"]["strings"])
                                            break

                                    section["data"]["sizes"] = [
                                        self.r16() for i in range(0, count)
                                    ]
                                case _:
                                    section["unknown"] = True
                                    self.buf.skip(self.buf.available())

                            block["data"]["sections"].append(section)
                            while self.buf.tell() % 4 != 0:
                                self.buf.skip(1)
                case _:
                    block["unknown"] = True
                    with self.buf.subunit():
                        block["data"]["blob"] = chew(self.buf)

            self.buf.sapunit()
            meta["blocks"].append(block)

        return meta


@module.register
class GitModule(module.RuminantModule):
    desc = "Git-related files."

    def identify(buf, ctx):
        if buf.available() < 6:
            return False

        if buf.peek(4) not in (b"blob", b"tree", b"comm"):
            return False

        try:
            with buf:
                line = buf.rzs()
                line = line.split(" ")
                assert len(line) == 2
                assert line[0] in ("blob", "tree", "commit")
                int(line[1])
                return True
        except Exception:
            return False

    def chew(self):
        meta = {}
        meta["type"] = "git"

        line = self.buf.rzs().split(" ")
        meta["header"] = {}
        meta["header"]["type"] = line[0]
        meta["header"]["length"] = int(line[1])

        self.buf.pasunit(meta["header"]["length"])

        match meta["header"]["type"]:
            case "tree":
                meta["data"] = []
                while self.buf.unit > 0:
                    line = self.buf.rzs().split(" ")
                    meta["data"].append({
                        "filename": line[1],
                        "mode": line[0],
                        "sha1": self.buf.rh(20)
                    })
            case "blob":
                with self.buf.subunit():
                    meta["data"] = chew(self.buf)
            case "commit":
                meta["data"] = {}
                meta["data"]["header"] = []
                while True:
                    line = utils.decode(self.buf.rl())
                    if line == "":
                        break

                    if line.startswith("gpgsig"):
                        line += "\n" + utils.decode(self.buf.rl()).strip()

                        while not line.endswith("-----"):
                            line += "\n" + utils.decode(self.buf.rl()).strip()

                    line = line.split(" ")
                    meta["data"]["header"].append({
                        "key": line[0],
                        "value": " ".join(line[1:])
                    })

                meta["data"]["commit-message"] = self.buf.rs(
                    self.buf.unit).strip().split("\n")

                for header in meta["data"]["header"]:
                    match header["key"]:
                        case "gpgsig":
                            header["parsed"] = chew(
                                header["value"].encode("utf-8"))
                        case "author" | "committer":
                            header["parsed"] = {}
                            line = header["value"].split(" ")
                            header["parsed"]["name"] = " ".join(line[:-3])
                            header["parsed"]["email"] = line[-3][1:-1]
                            header["parsed"]["timestamp"] = utils.unix_to_date(
                                int(line[-2]))
                            header["parsed"]["timezone"] = line[-1]

        self.buf.sapunit()

        return meta


@module.register
class IntelFlashModule(module.RuminantModule):
    dev = True
    desc = "Intel-based motherboard flash dumps.\nYou can extract yours if you're on an Intel system by installing flashrom and running 'flashrom -p internal -r flash.bin'."

    def identify(buf, ctx):
        if buf.available() < 32:
            return False

        return buf.peek(20)[16:20] == b"\x5a\xa5\xf0\x0f"

    def chew(self):
        meta = {}
        meta["type"] = "intel-flash"

        meta["flash-descriptor"] = {}

        self.buf.pasunit(4096)
        meta["flash-descriptor"]["reserved-vector"] = chew(self.buf.read(16),
                                                           blob_mode=True)
        meta["flash-descriptor"]["signature"] = hex(
            self.buf.ru32l())[2:].zfill(8)
        temp = self.buf.ru32l()
        meta["flash-descriptor"]["flmap0"] = {
            "raw": temp,
            "component-base": (temp >> 0) & ((1 << 8) - 1),
            "number-of-flash-chips": (temp >> 8) & ((1 << 2) - 1),
            "padding0": (temp >> 10) & ((1 << 6) - 1),
            "region-base": (temp >> 16) & ((1 << 8) - 1),
            "number-of-regions": (temp >> 24) & ((1 << 3) - 1),
            "padding1": (temp >> 27) & ((1 << 5) - 1)
        }
        meta["flash-descriptor"]["flmap1"] = {
            "raw": temp,
            "master-base": (temp >> 0) & ((1 << 8) - 1),
            "number-of-regions": (temp >> 8) & ((1 << 2) - 1),
            "padding0": (temp >> 10) & ((1 << 6) - 1),
            "pch-straps-base": (temp >> 16) & ((1 << 8) - 1),
            "number-of-pch-straps": (temp >> 24) & ((1 << 8) - 1)
        }
        meta["flash-descriptor"]["flmap2"] = {
            "raw": temp,
            "proc-straps-base": (temp >> 0) & ((1 << 8) - 1),
            "number-of-proc-straps": (temp >> 8) & ((1 << 8) - 1),
            "padding0": (temp >> 16) & ((1 << 16) - 1)
        }
        meta["flash-descriptor"]["flmap3"] = {
            "raw": temp,
        }

        self.buf.skip(3836 - self.buf.tell())
        meta["flash-descriptor"]["vscc-table-base"] = self.buf.ru8()
        meta["flash-descriptor"]["vscc-table-size"] = self.buf.ru8()
        meta["flash-descriptor"]["reserved9"] = self.buf.ru16()

        self.buf.sapunit()

        return meta


@module.register
class IntelMicrocodeModule(module.RuminantModule):
    desc = "Intel microcode files."

    def valid_bcd(val):
        return (val & 0x0f) < 10 and (val >> 4) < 10

    @classmethod
    def identify(cls, buf, ctx):
        if buf.available() < 48:
            return False

        with buf:
            if buf.ru32l() != 1:
                return False

            buf.skip(4)

            if not cls.valid_bcd(buf.ru8()):
                return False

            if buf.ru8() not in (0x19, 0x20):
                return False

            val = buf.ru8()
            if not cls.valid_bcd(val) or val > 0x31:
                return False

            if buf.ru8() not in (0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                 0x08, 0x09, 0x10, 0x11, 0x12):
                return False

            buf.seek(32)
            length = buf.ru32l()
            if length == 0:
                length = 2048

            buf.seek(0)

            if length % 4 != 0 or length > buf.available():
                return False

            s = 0
            for i in range(0, length, 4):
                s += buf.ru32l()

            return s & 0xffffffff == 0

    def chew(self):
        meta = {}
        meta["type"] = "intel-microcode"

        meta["header"] = {}
        meta["header"]["version"] = self.buf.ru32l()
        meta["header"]["revision"] = self.buf.ru32l()

        year = self.buf.ru16l()
        day = self.buf.ru8()
        month = self.buf.ru8()
        meta["header"][
            "date"] = f"{hex(year)[2:].zfill(4)}-{hex(month)[2:].zfill(2)}-{hex(day)[2:].zfill(2)}"
        meta["header"]["processor-signature"] = {"raw": self.buf.ru32l()}
        meta["header"]["processor-signature"]["hex"] = hex(
            meta["header"]["processor-signature"]["raw"])[2:].zfill(8)
        meta["header"]["processor-signature"]["stepping"] = (
            meta["header"]["processor-signature"]["raw"] >> 0) & 0x0f
        meta["header"]["processor-signature"]["model"] = (
            meta["header"]["processor-signature"]["raw"] >> 4) & 0x0f
        meta["header"]["processor-signature"]["family"] = (
            meta["header"]["processor-signature"]["raw"] >> 8) & 0x0f
        meta["header"]["processor-signature"]["processor-type"] = (
            meta["header"]["processor-signature"]["raw"] >> 12) & 0x03
        meta["header"]["processor-signature"]["extended-model"] = (
            meta["header"]["processor-signature"]["raw"] >> 16) & 0x0f
        meta["header"]["processor-signature"]["extended-family"] = (
            meta["header"]["processor-signature"]["raw"] >> 20) & 0xff

        family = meta["header"]["processor-signature"]["family"]
        model = meta["header"]["processor-signature"]["model"]
        if family == 0x0f:
            family += meta["header"]["processor-signature"]["extended-family"]
        if family in (0x06, 0x0f):
            model += meta["header"]["processor-signature"][
                "extended-model"] << 4

        meta["header"]["processor-signature"][
            "linux-name"] = f"{hex(family)[2:].zfill(2)}-{hex(model)[2:].zfill(2)}-{hex(meta['header']['processor-signature']['stepping'])[2:].zfill(2)}"
        meta["header"]["checksum"] = self.buf.rh(4)
        meta["header"]["loader-revision"] = self.buf.ru32l()
        meta["header"]["data-size"] = self.buf.ru32l()
        meta["header"]["total-size"] = self.buf.ru32l()
        meta["header"]["reserved"] = self.buf.rh(12)

        self.buf.pasunit((meta["header"]["total-size"] if meta["header"]
                          ["total-size"] != 0 else 2048) - self.buf.tell())

        with self.buf:
            has_exponent = False
            exponent_offset = 255

            with self.buf:
                self.buf.skip(255)

                while self.buf.unit > 4:
                    if self.buf.pu32l() == 17:
                        has_exponent = True
                        break

                    self.buf.skip(1)
                    exponent_offset += 1

            if has_exponent:
                meta["signature"] = {}
                with self.buf:
                    self.buf.skip(exponent_offset - 256)
                    meta["signature"]["public-key-offset"] = self.buf.tell()
                    meta["signature"]["modulus"] = self.buf.rh(256)
                    meta["signature"]["exponent"] = self.buf.ru32l()

                n = int.from_bytes(bytes.fromhex(meta["signature"]["modulus"]),
                                   "little")
                e = meta["signature"]["exponent"]

                with self.buf:
                    while self.buf.unit > 256:
                        c = int.from_bytes(self.buf.peek(256), "little")
                        m = pow(c, e, n)

                        if (m >> 2024) == 0x01ff:
                            meta["signature"][
                                "signature-offset"] = self.buf.tell()
                            meta["signature"][
                                "signature-encrypted"] = self.buf.rh(256)
                            meta["signature"]["signature-decrypted"] = hex(
                                m)[2:].zfill(512)
                            meta["signature"]["signature-hash"] = hex(
                                m)[2:].zfill(512)[448:]
                            break

                        self.buf.skip(1)

        with self.buf.subunit():
            meta["payload"] = chew(self.buf, blob_mode=True)

        self.buf.sapunit()

        return meta


@module.register
class BtrfsModule(module.RuminantModule):
    dev = True
    desc = "BTRFS filesystems."

    def identify(buf, ctx):
        if buf.available() < 0x10000:
            return False

        with buf:
            buf.seek(0x10040)
            return buf.peek(8) == b"_BHRfS_M"

    def chew(self):
        meta = {}
        meta["type"] = "btrfs"

        self.buf.seek(0x10000)
        meta["header"] = {}
        meta["header"]["checksum"] = self.buf.rh(32)
        meta["header"]["uuid"] = self.buf.ruuid()
        meta["header"]["header-paddr"] = self.buf.ru64l()
        meta["header"]["flags"] = self.buf.ru64l()
        self.buf.skip(8)
        meta["header"]["generation"] = self.buf.ru64l()
        meta["header"]["root-tree-laddr"] = self.buf.ru64l()
        meta["header"]["chunk-tree-laddr"] = self.buf.ru64l()
        meta["header"]["log-tree-laddr"] = self.buf.ru64l()
        meta["header"]["log-root-transid"] = self.buf.ru64l()
        meta["header"]["total-bytes"] = self.buf.ru64l()
        meta["header"]["bytes-used"] = self.buf.ru64l()
        meta["header"]["root-dir-object-id"] = self.buf.ru64l()
        meta["header"]["device-count"] = self.buf.ru64l()
        meta["header"]["sector-size"] = self.buf.ru32l()
        meta["header"]["node-size"] = self.buf.ru32l()
        meta["header"]["leaf-size"] = self.buf.ru32l()
        meta["header"]["stripe-size"] = self.buf.ru32l()
        meta["header"]["sys-chunk-array-size"] = self.buf.ru32l()
        meta["header"]["chunk-root-generation"] = self.buf.ru64l()
        meta["header"]["compat-flags"] = utils.unpack_flags(
            self.buf.ru64l(), constants.BTRFS_FLAGS)
        meta["header"]["compat-flags-ro"] = utils.unpack_flags(
            self.buf.ru64l(), constants.BTRFS_FLAGS)
        meta["header"]["incompat-flags"] = utils.unpack_flags(
            self.buf.ru64l(), constants.BTRFS_FLAGS)

        self.buf.seek(0)
        if meta["header"]["device-count"] == 1:
            self.buf.skip(meta["header"]["total-bytes"])
        else:
            self.buf.skip(self.buf.available())

        return meta

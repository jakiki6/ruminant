from .. import module, utils, constants
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
        meta["header"]["encoding"] = utils.unraw(
            self.buf.ru32(), 4, {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}
        )
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

        meta["schema"] = [x[0] for x in cur.execute("SELECT sql FROM sqlite_master")]

        db.close()
        fd.close()

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
                        root[k] = {"raw": v, "parsed": chew(base64.b64decode(v))}
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
                        self.buf.ru32(), datetime.timezone.utc
                    ).isoformat()

                    self.buf.seek(offset)
                    chunk["length"] = self.buf.ru32()
                    self.buf.pasunit(chunk["length"])

                    chunk["compression"] = utils.unraw(
                        self.buf.ru8(),
                        1,
                        {0x01: "GZip", 0x02: "zlib", 0x03: "Uncompressed"},
                    )

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
                        chunk["data"] = chew(data, extra_ctx={"skip-chunk-data": True})

                    self.buf.sapunit()

        m = 0x2000
        for chunk in meta["chunks"].values():
            m = max(m, chunk["offset"] + chunk["padded-length"])

        self.buf.seek(m)

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
        meta["header"]["magic"] = utils.unraw(
            self.buf.ru16l(), 2, constants.CPYTHON_MAGICS
        )
        self.buf.skip(2)
        meta["header"]["flags"] = self.buf.ru32l()
        if meta["header"]["flags"] & 0x0001:
            meta["header"]["source-hash"] = self.buf.rh(8)
        else:
            meta["header"]["timestamp"] = utils.unix_to_date(self.buf.ru32l())
            meta["header"]["source-length"] = self.buf.ru32l()

        meta["data"] = utils.read_marshal(self.buf, meta["header"]["magic"]["raw"])

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
        meta["mode"] = {"_v": "le32", "_V": "be32", "-v": "le64", "-V": "be64"}[
            self.buf.rs(2)
        ]
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
                                        self.buf.rzs()
                                        for i in range(0, section["data"]["count"])
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
                        "sha1": self.buf.rh(20),
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
                        "value": " ".join(line[1:]),
                    })

                meta["data"]["commit-message"] = (
                    self.buf.rs(self.buf.unit).strip().split("\n")
                )

                for header in meta["data"]["header"]:
                    match header["key"]:
                        case "gpgsig":
                            header["parsed"] = chew(header["value"].encode("utf-8"))
                        case "author" | "committer":
                            header["parsed"] = {}
                            line = header["value"].split(" ")
                            header["parsed"]["name"] = " ".join(line[:-3])
                            header["parsed"]["email"] = line[-3][1:-1]
                            header["parsed"]["timestamp"] = utils.unix_to_date(
                                int(line[-2])
                            )
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
        meta["flash-descriptor"]["reserved-vector"] = chew(
            self.buf.read(16), blob_mode=True
        )
        meta["flash-descriptor"]["signature"] = hex(self.buf.ru32l())[2:].zfill(8)
        temp = self.buf.ru32l()
        meta["flash-descriptor"]["flmap0"] = {
            "raw": temp,
            "component-base": (temp >> 0) & ((1 << 8) - 1),
            "number-of-flash-chips": (temp >> 8) & ((1 << 2) - 1),
            "padding0": (temp >> 10) & ((1 << 6) - 1),
            "region-base": (temp >> 16) & ((1 << 8) - 1),
            "number-of-regions": (temp >> 24) & ((1 << 3) - 1),
            "padding1": (temp >> 27) & ((1 << 5) - 1),
        }
        meta["flash-descriptor"]["flmap1"] = {
            "raw": temp,
            "master-base": (temp >> 0) & ((1 << 8) - 1),
            "number-of-regions": (temp >> 8) & ((1 << 2) - 1),
            "padding0": (temp >> 10) & ((1 << 6) - 1),
            "pch-straps-base": (temp >> 16) & ((1 << 8) - 1),
            "number-of-pch-straps": (temp >> 24) & ((1 << 8) - 1),
        }
        meta["flash-descriptor"]["flmap2"] = {
            "raw": temp,
            "proc-straps-base": (temp >> 0) & ((1 << 8) - 1),
            "number-of-proc-straps": (temp >> 8) & ((1 << 8) - 1),
            "padding0": (temp >> 16) & ((1 << 16) - 1),
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
            self.buf.ru64l(), constants.BTRFS_FLAGS
        )
        meta["header"]["compat-flags-ro"] = utils.unpack_flags(
            self.buf.ru64l(), constants.BTRFS_FLAGS
        )
        meta["header"]["incompat-flags"] = utils.unpack_flags(
            self.buf.ru64l(), constants.BTRFS_FLAGS
        )

        self.buf.seek(0)
        if meta["header"]["device-count"] == 1:
            self.buf.skip(meta["header"]["total-bytes"])
        else:
            self.buf.skip(self.buf.available())

        return meta


@module.register
class OpenTimestampsProofModule(module.RuminantModule):
    desc = "OpenTimestamps Proof files."

    def identify(buf, ctx):
        return (
            buf.peek(31)
            == b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94"
        )

    def read_op(self):
        op = {}
        opcode = self.buf.ru8()

        match opcode:
            case 0x00:
                op["type"] = "attestation"
                op["size"] = None
                op["payload"] = {}
                op["payload"]["attestation-type"] = utils.unraw(
                    self.buf.ru64(),
                    8,
                    {
                        0x83dfe30d2ef90c8e: "Pending",
                        0x0588960d73d71901: "BitcoinBlockHeader",
                    },
                    True,
                )

                op["size"] = self.buf.ruleb()
                self.buf.pasunit(op["size"])

                match op["payload"]["attestation-type"]:
                    case "Pending":
                        op["payload"]["uri"] = self.buf.rs(self.buf.ruleb())
                    case "BitcoinBlockHeader":
                        op["payload"]["block-height"] = self.buf.ruleb()
                    case _:
                        op["payload"]["raw"] = self.buf.rh(self.buf.unit)

                self.buf.sapunit()
            case 0x08:
                op["type"] = "sha256"
            case 0xf0:
                op["type"] = "append"
                op["size"] = self.buf.ruleb()
                op["payload"] = self.buf.rh(op["size"])
            case 0xf1:
                op["type"] = "prepend"
                op["size"] = self.buf.ruleb()
                op["payload"] = self.buf.rh(op["size"])
            case 0xff:
                op["type"] = "fork"
                op["payload"] = {}
                op["payload"]["children"] = []
            case _:
                raise ValueError(f"Unknown opcode (0x{hex(opcode)[2:].zfill(2)})")

        return op

    def read_ops(self):
        ops = []

        level = 1
        while level > 0:
            ops.append(self.read_op())
            if ops[-1]["type"] == "attestation":
                level -= 1
            elif ops[-1]["type"] == "fork":
                level += 1

        root = []

        tree = root
        stack = [tree]
        while len(ops):
            elem = ops.pop(0)
            tree.append(elem)

            if elem["type"] == "fork":
                stack.append(tree)
                tree = []
                elem["payload"]["children"] = tree
            elif elem["type"] == "attestation":
                tree = stack.pop()

        return root

    def chew(self):
        meta = {}
        meta["type"] = "opentimestamps-proof"

        self.buf.skip(31)
        meta["version"] = self.buf.ru8()

        match meta["version"]:
            case 0x01:
                meta["file-hash-op"] = self.read_op()
                meta["file-hash"] = self.buf.rh(
                    {"sha256": 32}[meta["file-hash-op"]["type"]]
                )
                meta["timestamp"] = self.read_ops()
            case _:
                meta["unknown"] = True

        return meta

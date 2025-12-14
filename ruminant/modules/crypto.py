from .. import module, utils
from ..buf import Buf
from ..constants import AGE_DRAND_CHAINS
from . import chew
import base64
import hashlib
import json


@module.register
class DerModule(module.RuminantModule):
    priority = 1
    desc = "ASN.1 DER binary files detected on a best-effort basis."

    def identify(buf, ctx):
        return buf.pu8() == 0x30 and (buf.pu16() & 0xf0) in (0x80, 0x30)

    def chew(self):
        meta = {}
        meta["type"] = "der"

        meta["data"] = []
        while True:
            bak = self.buf.backup()

            try:
                meta["data"].append(utils.read_der(self.buf))
            except Exception:
                self.buf.restore(bak)
                break

        return meta


@module.register
class PemModule(module.RuminantModule):
    desc = "PEM encoded files."

    def identify(buf, ctx):
        return buf.peek(27) == b"-----BEGIN CERTIFICATE-----" or buf.peek(
            15) == b"-----BEGIN RSA " or buf.peek(
                26) == b"-----BEGIN PUBLIC KEY-----" or buf.peek(
                    27) == b"-----BEGIN PRIVATE KEY-----" or buf.peek(
                        30) == b"-----BEGIN EC PRIVATE KEY-----"

    def chew(self):
        meta = {}
        meta["type"] = "pem"

        self.buf.rl()

        content = b""
        while True:
            line = self.buf.rl()
            if self.buf.available() == 0 or line.startswith(b"-----END"):
                break

            content += line

        while self.buf.peek(1) in (b"\r", b"\n"):
            self.buf.skip(1)

        meta["data"] = utils.read_der(Buf(base64.b64decode(content)))

        return meta


@module.register
class PgpModule(module.RuminantModule):
    desc = "Binary or armored PGP files."

    def identify(buf, ctx):
        if buf.available() > 4 and buf.pu8() in (
                0x85, 0x89) and buf.peek(4)[3] in (0x03, 0x04):
            return True

        return buf.peek(15) == b"-----BEGIN PGP "

    def chew(self):
        meta = {}
        meta["type"] = "pgp"

        if self.buf.peek(1) == b"-":
            if self.buf.rl() == b"-----BEGIN PGP SIGNED MESSAGE-----":
                message = b""

                meta["message-hash"] = self.buf.rl().split(b": ")[1].decode(
                    "utf-8")
                self.buf.rl()

                while True:
                    line = self.buf.rl()

                    if self.buf.available(
                    ) == 0 or line == b"-----BEGIN PGP SIGNATURE-----":
                        break

                    message += line + b"\n"

                meta["message"] = utils.decode(message).split("\n")[:-1]

            content = b""
            while True:
                line = self.buf.rl()
                if self.buf.available() == 0 or line.startswith(
                        b"-----END PGP "):
                    break

                if b":" in line:
                    continue

                content += line

            while self.buf.peek(1) in (b"\r", b"\n"):
                self.buf.skip(1)

            if b"=" in content:
                while content[-1] != b"="[0]:
                    content = content[:-1]

            fd = Buf(base64.b64decode(content))
        else:
            fd = self.buf

        meta["data"] = []
        while fd.available() > 0:
            meta["data"].append(utils.read_pgp(fd))

        return meta


@module.register
class KdbxModule(module.RuminantModule):
    desc = "KeePass database files."

    def identify(buf, ctx):
        return buf.peek(8) == b"\x03\xd9\xa2\x9ag\xfbK\xb5"

    def chew(self):
        meta = {}
        meta["type"] = "kdbx"

        self.buf.skip(8)
        version = self.buf.ru32l()
        meta["version"] = f"{version >> 16}.{version & 0xffff}"

        meta["fields"] = []
        running = True
        while running:
            field = {}
            typ = self.buf.ru8()

            length = self.buf.ru32l()
            self.buf.pushunit()
            self.buf.setunit(length)

            match typ:
                case 0x00:
                    field["type"] = "End of header"
                    running = False
                case 0x02:
                    field["type"] = "Encryption algorithm"
                    uuid = utils.to_uuid(self.buf.read(16))
                    field["algorithm"] = {
                        "raw": uuid,
                        "name": {
                            "31c1f2e6-bf71-4350-be58-05216afc5aff":
                            "AES-256 (NIST FIPS 197, CBC mode, PKCS #7 padding)",
                            "d6038a2b-8b6f-4cb5-a524-339a31dbb59a":
                            "ChaCha20 (RFC 8439)"
                        }.get(uuid, "Unknown")
                    }
                case 0x03:
                    field["type"] = "Compression algorithm"
                    field["algorithm"] = utils.unraw(self.buf.ru32l(), 4, {
                        0: "No compression",
                        1: "GZip"
                    })
                case 0x04:
                    field["type"] = "Master salt/seed"
                    field["salt"] = self.buf.rh(32)
                case 0x07:
                    field["type"] = "Encryption IV/nonce"
                    field["iv"] = self.buf.rh(self.buf.unit)
                case 0x0b | 0x0c:
                    field["type"] = {
                        0x0b: "KDF parameters",
                        0x0c: "Public custom data"
                    }.get(typ)

                    field["dict"] = {}
                    version = self.buf.ru16l()
                    field["dict"][
                        "version"] = f"{version >> 8}.{version & 0xff}"

                    field["dict"]["entries"] = []

                    running2 = True
                    while running2:
                        entry = {}
                        typ2 = self.buf.ru8()
                        if typ2 == 0x00:
                            entry["type"] = "end"
                            running2 = False
                        else:
                            entry["name"] = self.buf.rs(self.buf.ru32l())

                            length2 = self.buf.ru32l()

                            self.buf.pushunit()
                            self.buf.setunit(length2)

                            match typ2:
                                case 0x04:
                                    entry["type"] = "uint32"
                                    entry["data"] = self.buf.ru32l()
                                case 0x05:
                                    entry["type"] = "uint64"
                                    entry["data"] = self.buf.ru64l()
                                case 0x08:
                                    entry["type"] = "boolean"
                                    entry["data"] = bool(self.buf.ru8())
                                case 0x0c:
                                    entry["type"] = "int32"
                                    entry["data"] = self.buf.ri32l()
                                case 0x0d:
                                    entry["type"] = "int64"
                                    entry["data"] = self.buf.ri64l()
                                case 0x18:
                                    entry["type"] = "string"
                                    entry["data"] = self.buf.rs(self.buf.unit)
                                case 0x42:
                                    entry["type"] = "bytes"
                                    entry["data"] = self.buf.rh(self.buf.unit)
                                case _:
                                    entry[
                                        "type"] = f"Unknown (0x{hex(typ2)[2:].zfill(2)})"

                            match entry["name"], entry["type"]:
                                case "$UUID", "bytes":
                                    entry["data"] = utils.to_uuid(
                                        bytes.fromhex(entry["data"]))
                                    entry["data"] = {
                                        "raw": entry["data"],
                                        "name": {
                                            "c9d9f39a-628a-4460-bf74-0d08c18a4fea":
                                            "AES-KDF",
                                            "ef636ddf-8c29-444b-91f7-a9a403e30a0c":
                                            "Argon2d",
                                            "9e298b19-56db-4773-b23d-fc3ec6f0a1e6":
                                            "Argon2id"
                                        }.get(entry["data"], "Unknown")
                                    }

                            self.buf.skipunit()
                            self.buf.popunit()

                        field["dict"]["entries"].append(entry)
                case _:
                    field["type"] = f"Unknown (0x{hex(typ)[2:].zfill(2)})"

            self.buf.skipunit()
            self.buf.popunit()

            meta["fields"].append(field)

        meta["sha256"] = {}
        meta["sha256"]["value"] = self.buf.rh(32)
        with self.buf:
            length = self.buf.tell() - 32
            self.buf.seek(0)
            sha256_hash = hashlib.sha256(self.buf.read(length)).hexdigest()

            meta["sha256"]["correct"] = meta["sha256"]["value"] == sha256_hash
            if not meta["sha256"]["correct"]:
                meta["sha256"]["actual"] = sha256_hash

        meta["hmac-sha256"] = self.buf.rh(32)

        meta["block-count"] = 0
        while self.buf.available() > 0:
            meta["block-count"] += 1
            self.buf.skip(32)
            self.buf.skip(self.buf.ru32l())

        return meta


@module.register
class AgeModule(module.RuminantModule):
    desc = "age encrypted files including the tlock extension."

    def identify(buf, ctx):
        return buf.peek(
            34) == b"-----BEGIN AGE ENCRYPTED FILE-----" or buf.peek(
                20) == b"age-encryption.org/v"

    def chew(self):
        meta = {}
        meta["type"] = "age"

        meta["data"] = {}
        meta["data"]["armored"] = self.buf.peek(1) == b"-"

        if meta["data"]["armored"]:
            self.buf.rl()

            content = b""
            while True:
                line = self.buf.rl()
                if line.startswith(b"----"):
                    break

                content += line

            content = base64.b64decode(content)
            return chew(content)

        self.buf.skip(20)
        meta["data"]["version"] = int(self.buf.rl())

        match meta["data"]["version"]:
            case 1:
                meta["data"]["stanzas"] = []

                while True:
                    stanza = {}

                    line = self.buf.rl()
                    if line.startswith(b"---"):
                        meta["data"]["header-mac"] = base64.b64decode(
                            line[4:] + b"==").hex()
                        break

                    stanza["type"] = utils.decode(line).split(" ")[1]
                    stanza["arguments"] = {}
                    args = utils.decode(line).split(" ")[2:]
                    match stanza["type"]:
                        case "X25519":
                            stanza["arguments"]["ephemeral-share"] = args[
                                0].hex()
                        case "scrypt":
                            stanza["arguments"]["salt"] = base64.b64decode(
                                args[0] + "==").hex()
                            stanza["arguments"]["work"] = 1 << int(args[1])
                        case "tlock":
                            stanza["arguments"]["round"] = int(args[0])
                            stanza["arguments"]["chain"] = args[1]

                            if stanza["arguments"][
                                    "chain"] in AGE_DRAND_CHAINS:
                                chain = AGE_DRAND_CHAINS[stanza["arguments"]
                                                         ["chain"]]
                                stanza["parsed"] = {}
                                stanza["parsed"]["chain-name"] = chain["name"]
                                stanza["parsed"][
                                    "decryption-time"] = utils.unix_to_date(
                                        chain["genesis"] + chain["period"] *
                                        (stanza["arguments"]["round"] - 1))
                        case _:
                            stanza["arguments"] = args
                            stanza["unknown"] = True

                    line = b""
                    while self.buf.peek(3) not in (b"---", b"-> "):
                        line += self.buf.rl()

                    stanza["wrapped-key"] = base64.b64decode(line +
                                                             b"==").hex()

                    meta["data"]["stanzas"].append(stanza)

                meta["data"]["block-count"] = (self.buf.available() + 65536 +
                                               15) // (65536 + 16)
                self.buf.skip(self.buf.available())
            case _:
                meta["unknown"] = True

        return meta


@module.register
class LuksModule(module.RuminantModule):
    desc = "Linux Unified Key Setup version 1 and 2 headers."

    def identify(buf, ctx):
        return buf.peek(6) == b"LUKS\xba\xbe"

    def chew(self):
        meta = {}
        meta["type"] = "luks"

        self.buf.skip(6)
        meta["header"] = {}
        meta["header"]["version"] = self.buf.ru16()

        match meta["header"]["version"]:
            case 1:
                meta["header"]["cipher-name"] = self.buf.rs(32)
                meta["header"]["cipher-mode"] = self.buf.rs(32)
                meta["header"]["hash-spec"] = self.buf.rs(32)
                meta["header"]["payload-offset"] = self.buf.ru32()
                meta["header"]["key-bytes"] = self.buf.ru32()
                meta["header"]["mk-digest"] = self.buf.rh(20)
                meta["header"]["mk-digest-salt"] = self.buf.rh(32)
                meta["header"]["mk-digest-iter"] = self.buf.ru32()
                meta["header"]["uuid"] = self.buf.rs(40)

                meta["header"]["key-slots"] = []
                for i in range(0, 8):
                    ks = {}
                    ks["active"] = utils.unraw(self.buf.ru32(), 4, {
                        0x0000dead: "disabled",
                        0x00ac71f3: "enabled"
                    }, True)
                    ks["iterations"] = self.buf.ru32()
                    ks["salt"] = self.buf.rh(32)
                    ks["key-material-offset"] = self.buf.ru32()
                    ks["stripes"] = self.buf.ru32()
                    meta["header"]["key-slots"].append(ks)

                self.buf.skip(self.buf.available())
            case 2:
                meta["header"]["header-length"] = self.buf.ru64()

                self.buf.pasunit(meta["header"]["header-length"] - 16)

                meta["header"]["sequence-id"] = self.buf.ru64()
                meta["header"]["label"] = self.buf.rs(48)
                meta["header"]["checksum-algorithm"] = self.buf.rs(32)
                meta["header"]["salt"] = self.buf.rh(64)
                meta["header"]["uuid"] = self.buf.rs(40)
                meta["header"]["subsystem"] = self.buf.rs(48)
                meta["header"]["header-offset"] = self.buf.ru64()
                self.buf.skip(184)
                meta["header"]["checksum"] = self.buf.rh(64)
                self.buf.skip(7 * 512)

                if meta["header"]["version"] == 2:
                    meta["json"] = json.loads(self.buf.rs(self.buf.unit))

                self.buf.sapunit()

                m = 0
                for _, v in meta["json"].get("segments", {}).items():
                    if v.get("size") == "dynamic":
                        m = self.buf.size()
                        break

                    m = max(m, int(v.get("offset", 0)) + int(v.get("size", 0)))

                self.buf.seek(m)
            case _:
                meta["unknown"] = True

        return meta


@module.register
class SshSignatureModule(module.RuminantModule):
    desc = "SSH signatures like the ones that Git uses."

    def identify(buf, ctx):
        return buf.peek(29) == b"-----BEGIN SSH SIGNATURE-----"

    def rb(self, buf=None):
        if buf is None:
            buf = self.ibuf

        return buf.read(self.ibuf.ru32())

    def rs(self, buf=None):
        if buf is None:
            buf = self.ibuf

        return buf.rs(self.ibuf.ru32())

    def chew(self):
        meta = {}
        meta["type"] = "ssh-signature"

        self.buf.rl()
        lines = b""
        while True:
            line = self.buf.rl()
            if line == b"-----END SSH SIGNATURE-----":
                break

            lines += line

        self.ibuf = Buf(base64.b64decode(lines))
        self.ibuf.skip(6)

        meta["data"] = {}
        meta["data"]["version"] = self.ibuf.ru32()

        self.ibuf.pasunit(self.ibuf.ru32())
        meta["data"]["public-key"] = {}
        meta["data"]["public-key"]["algorithm"] = self.rs()
        meta["data"]["public-key"]["blob"] = self.rb().hex()
        self.ibuf.sapunit()

        meta["data"]["namespace"] = self.rs()
        meta["data"]["reserved"] = self.rs()
        meta["data"]["hash-algorithm"] = self.rs()

        self.ibuf.pasunit(self.ibuf.ru32())
        meta["data"]["signature"] = {}
        meta["data"]["signature"]["algorithm"] = self.rs()
        meta["data"]["signature"]["blob"] = self.rb().hex()
        self.ibuf.sapunit()

        return meta


@module.register
class OpenSshPrivateKeyModule(module.RuminantModule):
    dev = True
    desc = "OpenSSH private keys."

    def identify(buf, ctx):
        return buf.peek(35) == b"-----BEGIN OPENSSH PRIVATE KEY-----"

    def rb(self, buf=None):
        if buf is None:
            buf = self.ibuf

        return buf.read(self.ibuf.ru32())

    def rs(self, buf=None):
        if buf is None:
            buf = self.ibuf

        return buf.rs(self.ibuf.ru32())

    def chew(self):
        meta = {}
        meta["type"] = "openssh-private-key"

        self.buf.rl()
        lines = b""
        while True:
            line = self.buf.rl()
            if line == b"-----END OPENSSH PRIVATE KEY-----":
                break

            lines += line

        self.ibuf = Buf(base64.b64decode(lines))

        meta["data"] = {}
        meta["data"]["magic"] = self.ibuf.rzs()
        if meta["data"]["magic"] != "openssh-key-v1":
            meta["unknown"] = True
            return meta

        meta["data"]["cipher"] = self.rs()
        meta["data"]["kdfname"] = self.rs()
        match meta["data"]["kdfname"]:
            case "none":
                meta["data"]["kdfoptions"] = self.rs()
            case "bcrypt":
                meta["data"]["kdfoptions"] = {
                    "salt": self.rs(),
                    "rounds": self.ibuf.ru32()
                }
            case _:
                meta["unknown"] = True
                return meta
        meta["data"]["nkeys"] = self.ibuf.ru32()
        meta["data"]["public-keys"] = [
            self.rb().hex() for i in range(0, meta["data"]["nkeys"])
        ]

        return meta


@module.register
class VbmetaModule(module.RuminantModule):
    desc = "vbmeta partitions from AVB."

    def identify(buf, ctx):
        return buf.peek(4) == b"AVB0"

    def read_pubkey(self, algo):
        key = {}

        match algo:
            case "SHA256_RSA2048" | "SHA256_RSA4096" | "SHA256_RSA8192" | "SHA512_RSA2048" | "SHA512_RSA4096" | "SHA512_RSA8192":
                bits = self.buf.ru32()
                key["bits"] = bits
                key["n0inv"] = self.buf.ru32()
                key["modulus"] = int.from_bytes(self.buf.read(
                    (bits + 7) // 8)) & ((1 << bits) - 1)
                key["rrmodn"] = int.from_bytes(self.buf.read(
                    (bits + 7) // 8)) & ((1 << bits) - 1)

                n = key["modulus"]
                key["n0inv-correct"] = key["n0inv"] == 2**32 - pow(
                    n, -1, 2**32)
                key["rrmodn-correct"] = key["rrmodn"] == 2**(key["bits"] *
                                                             2) % n

        return key

    def chew(self):
        meta = {}
        meta["type"] = "vbmeta"

        self.buf.skip(4)
        meta["header"] = {}
        meta["header"][
            "libavb-version"] = f"{self.buf.ru32()}.{self.buf.ru32()}"
        meta["header"]["authentication-data-block-size"] = self.buf.ru64()
        meta["header"]["auxiliary-data-block-size"] = self.buf.ru64()
        meta["header"]["algorithm-type"] = utils.unraw(
            self.buf.ru32(), 4, {
                0x00: "NONE",
                0x01: "SHA256_RSA2048",
                0x02: "SHA256_RSA4096",
                0x03: "SHA256_RSA8192",
                0x04: "SHA512_RSA2048",
                0x05: "SHA512_RSA4096",
                0x06: "SHA512_RSA8192"
            })
        meta["header"]["hash-offset"] = self.buf.ru64()
        meta["header"]["hash-size"] = self.buf.ru64()
        meta["header"]["signature-offset"] = self.buf.ru64()
        meta["header"]["signature-size"] = self.buf.ru64()
        meta["header"]["public-key-offset"] = self.buf.ru64()
        meta["header"]["public-key-size"] = self.buf.ru64()
        meta["header"]["public-key-metadata-offset"] = self.buf.ru64()
        meta["header"]["public-key-metadata-size"] = self.buf.ru64()
        meta["header"]["descriptors-offset"] = self.buf.ru64()
        meta["header"]["descriptors-size"] = self.buf.ru64()
        temp = self.buf.ru64()
        meta["header"]["rollback-index"] = {
            "raw": temp,
            "date": utils.unix_to_date(temp)
        }
        meta["header"]["flags"] = utils.unpack_flags(self.buf.ru32(), [])
        meta["header"]["rollback-index-location"] = self.buf.ru32()
        meta["header"]["release-string"] = self.buf.rs(48)
        meta["header"]["padding"] = chew(self.buf.read(128), blob_mode=True)

        meta["authentication-data-block"] = {}
        self.buf.seek(256 + meta["header"]["hash-offset"])
        meta["authentication-data-block"]["hash"] = self.buf.rh(
            meta["header"]["hash-size"])
        self.buf.seek(256 + meta["header"]["signature-offset"])
        meta["authentication-data-block"]["signature"] = self.buf.rh(
            meta["header"]["signature-size"])

        meta["auxiliary-data-block"] = {}

        self.buf.seek(256 + meta["header"]["authentication-data-block-size"] +
                      meta["header"]["descriptors-offset"])
        self.buf.pasunit(meta["header"]["descriptors-size"])

        meta["auxiliary-data-block"]["descriptors"] = []
        while self.buf.unit > 0:
            tag = {}
            typ = self.buf.ru64()
            tag["type"] = None
            tag["length"] = self.buf.ru64()
            tag["payload"] = {}

            self.buf.pasunit(tag["length"])
            match typ:
                case 0x00:
                    tag["type"] = "PROPERTY"
                    klen = self.buf.ru64()
                    vlen = self.buf.ru64()
                    tag["payload"]["key"] = self.buf.rs(klen)
                    self.buf.skip(1)
                    tag["payload"]["value"] = self.buf.rs(vlen)
                    self.buf.skip(1)
                case 0x01:
                    tag["type"] = "HASHTREE"
                    tag["payload"]["dm-verity-version"] = self.buf.ru32()
                    tag["payload"]["image-size"] = self.buf.ru64()
                    tag["payload"]["tree-offset"] = self.buf.ru64()
                    tag["payload"]["tree-size"] = self.buf.ru64()
                    tag["payload"]["data-block-size"] = self.buf.ru32()
                    tag["payload"]["hash-block-size"] = self.buf.ru32()
                    tag["payload"]["fec-num-roots"] = self.buf.ru32()
                    tag["payload"]["fec-offset"] = self.buf.ru64()
                    tag["payload"]["fec-size"] = self.buf.ru64()
                    tag["payload"]["hash-name"] = self.buf.rs(32)
                    tag["payload"]["partition-name-length"] = self.buf.ru32()
                    tag["payload"]["salt-length"] = self.buf.ru32()
                    tag["payload"]["root-digest-length"] = self.buf.ru32()
                    tag["payload"]["flags"] = utils.unpack_flags(
                        self.buf.ru32(), [])
                    tag["payload"]["reserved"] = chew(self.buf.read(60),
                                                      blob_mode=True)
                    tag["payload"]["partition-name"] = self.buf.rs(
                        tag["payload"]["partition-name-length"])
                    tag["payload"]["salt"] = self.buf.rh(
                        tag["payload"]["salt-length"])
                    tag["payload"]["root-digest"] = self.buf.rh(
                        tag["payload"]["root-digest-length"])
                case 0x02:
                    tag["type"] = "HASH"
                    tag["payload"]["image-size"] = self.buf.ru64()
                    tag["payload"]["hash-name"] = self.buf.rs(32)
                    tag["payload"]["partition-name-length"] = self.buf.ru32()
                    tag["payload"]["salt-length"] = self.buf.ru32()
                    tag["payload"]["root-digest-length"] = self.buf.ru32()
                    tag["payload"]["reserved"] = chew(self.buf.read(64),
                                                      blob_mode=True)
                    tag["payload"]["partition-name"] = self.buf.rs(
                        tag["payload"]["partition-name-length"])
                    tag["payload"]["salt"] = self.buf.rh(
                        tag["payload"]["salt-length"])
                    tag["payload"]["root-digest"] = self.buf.rh(
                        tag["payload"]["root-digest-length"])
                case 0x03:
                    tag["type"] = "KERNEL_CMDLINE"
                    tag["payload"]["flags"] = utils.unpack_flags(
                        self.buf.ru32(), [])
                    tag["payload"]["cmdline"] = self.buf.rs(self.buf.ru32())
                case 0x04:
                    tag["type"] = "CHAIN_PARTITION"
                    tag["payload"]["rollback-index-location"] = self.buf.ru32()
                    tag["payload"]["parition-name-length"] = self.buf.ru32()
                    tag["payload"]["public-key-length"] = self.buf.ru32()
                    tag["payload"]["flags"] = utils.unpack_flags(
                        self.buf.ru32(), [])
                    tag["payload"]["reserved"] = chew(self.buf.read(60),
                                                      blob_mode=True)
                    tag["payload"]["partition-name"] = self.buf.rs(
                        tag["payload"]["parition-name-length"])
                    tag["payload"]["public-key"] = self.read_pubkey(
                        meta["header"]["algorithm-type"]["name"])
                case _:
                    tag["type"] = f"UNKNOWN (0x{hex(typ)[2:].zfill(16)})"
                    tag["payload"]["blob"] = chew(self.buf.readunit())

            self.buf.sapunit()

            if tag["length"] % 8:
                self.buf.skip(8 - (tag["length"] % 8))

            meta["auxiliary-data-block"]["descriptors"].append(tag)

        self.buf.sapunit()

        if meta["header"]["public-key-size"]:
            self.buf.seek(256 +
                          meta["header"]["authentication-data-block-size"] +
                          meta["header"]["public-key-offset"])
            self.buf.pasunit(meta["header"]["public-key-size"])

            meta["auxiliary-data-block"]["public-key"] = self.read_pubkey(
                meta["header"]["algorithm-type"]["name"])
            if "RSA" in meta["header"]["algorithm-type"]["name"]:
                sig = pow(
                    int(meta["authentication-data-block"]["signature"],
                        16), 65537, meta["auxiliary-data-block"]["public-key"]
                    ["modulus"]).to_bytes(
                        len(meta["authentication-data-block"]["signature"]) //
                        2, "big")
                sig = sig[2:].lstrip(b"\xff")[1:]
                meta["auxiliary-data-block"]["public-key"][
                    "signature"] = utils.read_der(Buf(sig))

            self.buf.sapunit()

        if meta["header"]["public-key-metadata-size"]:
            self.buf.seek(256 +
                          meta["header"]["authentication-data-block-size"] +
                          meta["header"]["public-key-metadata-offset"])
            self.buf.pasunit(meta["header"]["public-key-metadata-size"])

            with self.buf.subunit():
                meta["auxiliary-data-block"]["public-key-metadata"] = chew(
                    self.buf)

            self.buf.sapunit()

        while self.buf.tell() % 4096:
            self.buf.skip(1)

        return meta

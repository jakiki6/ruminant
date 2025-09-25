from .. import module, utils, buf
import base64
import hashlib


@module.register
class DerModule(module.RuminantModule):

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

    def identify(buf, ctx):
        return buf.peek(27) == b"-----BEGIN CERTIFICATE-----" or buf.peek(
            15) == b"-----BEGIN RSA " or buf.peek(
                26) == b"-----BEGIN PUBLIC KEY-----" or buf.peek(
                    27) == b"-----BEGIN PRIVATE KEY-----"

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

        meta["data"] = utils.read_der(buf.Buf(base64.b64decode(content)))

        return meta


@module.register
class PgpModule(module.RuminantModule):

    def identify(buf, ctx):
        if buf.pu8() in (0x85, 0x89) and buf.peek(4)[3] in (0x03, 0x04):
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

            fd = buf.Buf(base64.b64decode(content))
        else:
            fd = self.buf

        meta["data"] = []
        while fd.available() > 0:
            meta["data"].append(utils.read_pgp(fd))

        return meta


@module.register
class KdbxModule(module.RuminantModule):

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

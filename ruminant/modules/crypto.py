from .. import module, utils, buf
import base64


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

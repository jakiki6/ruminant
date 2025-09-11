from .. import module, utils
from . import chew
import zlib
import json


@module.register
class FlacModule(module.RuminantModule):

    def identify(buf, ctx):
        return buf.peek(4) == b"fLaC"

    def chew(self):
        meta = {}
        meta["type"] = "flac"

        self.buf.skip(4)

        meta["blocks"] = []
        more = True
        while more:
            block = {}
            block["type"] = None

            flags = self.buf.ru8()
            more = not bool(flags & 0x80)
            typ = flags & 0x7f

            length = self.buf.ru24()
            block["length"] = length

            self.buf.pushunit()
            self.buf.setunit(length)

            block["data"] = {}
            match typ:
                case 0:
                    block["type"] = "Streaminfo"
                    block["data"]["min-block-size"] = self.buf.ru16()
                    block["data"]["max-block-size"] = self.buf.ru16()
                    block["data"]["min-frame-size"] = self.buf.ru24()
                    block["data"]["max-frame-size"] = self.buf.ru24()

                    temp = self.buf.ru64()
                    block["data"]["sample-rate"] = temp >> 44
                    block["data"]["channel-count"] = ((temp >> 41) & 0x07) + 1
                    block["data"]["bits-per-sample"] = (
                        (temp >> 36) & 0x1f) + 1
                    block["data"]["sample-count"] = temp & 0xfffffffff

                    block["data"]["unencoded-md5"] = self.buf.rh(16)
                case 1:
                    block["type"] = "Padding"
                    block["data"]["non-zero"] = sum(self.buf.readunit()) > 0
                case 2:
                    block["type"] = "Application"
                    block["data"]["application-id"] = self.buf.rs(4, "latin-1")
                case 4:
                    block["type"] = "Vorbis comment"
                    block["data"]["vendor-string"] = self.buf.rs(
                        self.buf.ru32l())

                    block["data"]["user-strings"] = []
                    for i in range(0, self.buf.ru32l()):
                        block["data"]["user-strings"].append(
                            self.buf.rs(self.buf.ru32l()))
                case 6:
                    block["type"] = "Picture"
                    picture_type = self.buf.ru32()
                    block["data"]["picture-type"] = {
                        0: "Other",
                        1: "PNG file icon of 32x32 pixels (see [RFC2083])",
                        2: "General file icon",
                        3: "Front cover",
                        4: "Back cover",
                        5: "Liner notes page",
                        6: "Media label (e.g., CD, Vinyl or Cassette label)",
                        7: "Lead artist, lead performer, or soloist",
                        8: "Artist or performer",
                        9: "Conductor",
                        10: "Band or orchestra",
                        11: "Composer",
                        12: "Lyricist or text writer",
                        13: "Recording location",
                        14: "During recording",
                        15: "During performance",
                        16: "Movie or video screen capture",
                        17: "A bright colored fish",
                        18: "Illustration",
                        19: "Band or artist logotype",
                        20: "Publisher or studio logotype"
                    }.get(picture_type,
                          "Unknown") + f" (0x{hex(picture_type)[2:].zfill(4)})"
                    block["data"]["media-type"] = self.buf.rs(self.buf.ru32())
                    block["data"]["description"] = self.buf.rs(self.buf.ru32())
                    block["data"]["width"] = self.buf.ru32()
                    block["data"]["height"] = self.buf.ru32()
                    block["data"]["bits-per-pixel"] = self.buf.ru32()
                    block["data"]["palette-element-count"] = self.buf.ru32()
                    block["data"]["picture"] = chew(
                        self.buf.read(self.buf.ru32()))
                case _:
                    block["type"] = f"Unknown (0x{hex(typ)[2:].zfill(2)})"
                    block["unknown"] = True

            meta["blocks"].append(block)

            self.buf.skipunit()
            self.buf.popunit()

        return meta


@module.register
class ID3v2Module(module.RuminantModule):

    def identify(buf, ctx):
        return buf.peek(3) == b"ID3"

    def read_length(self, unsynchronized):
        if unsynchronized or self.force:
            length = 0

            for i in range(0, 4):
                length <<= 7
                length |= self.buf.ru8() & 0x7f

            return length
        else:
            return self.buf.ru32()

    def chew(self):
        self.force = False

        bak = self.buf.backup()
        try:
            return self._chew()
        except AssertionError:
            self.force = True
            self.buf.restore(bak)
            return self._chew()

    def _chew(self):
        meta = {}
        meta["type"] = "id3v2"

        self.buf.skip(3)
        meta["header"] = {}
        meta["header"]["version"] = str("2." + str(self.buf.ru8()) + "." +
                                        str(self.buf.ru8()))

        flags = self.buf.ru8()
        meta["header"]["flags"] = {
            "raw": flags,
            "unsynchronized": bool(flags & 0x80),
            "has-extended-header": bool(flags & 0x40),
            "experimental": bool(flags & 0x20),
            "has-footer": bool(flags & 0x10),
        }

        meta["header"]["length"] = self.read_length(bool(flags & 0x80))
        self.buf.pushunit()
        self.buf.setunit(meta["header"]["length"])

        if meta["header"]["flags"]["has-extended-header"]:
            meta["extended-header"] = {}

            extended_header_length = self.read_length(bool(flags & 0x80))
            meta["extended-header"]["length"] = extended_header_length

            self.buf.pushunit()
            self.buf.setunit(extended_header_length - 4)

            meta["extended-header"]["flags"] = self.buf.rh(self.buf.ru8())

            meta["extended-header"]["flag-values"] = []
            while self.buf.unit > 0:
                meta["extended-header"]["flag-values"].append(
                    self.buf.rh(self.buf.ru8()))

            self.buf.skipunit()
            self.buf.popunit()

        meta["frames"] = []
        while self.buf.unit > 0:
            frame = {}
            frame["type"] = self.buf.rs(4)
            if frame["type"] == "\x00\x00\x00\x00":
                break

            frame["length"] = self.read_length(bool(flags & 0x80))

            status_flags = self.buf.ru8()
            frame["status-flags"] = {
                "raw": status_flags,
                "discard-on-tag-alter": bool(status_flags & 0b01000000),
                "discard-on-file-alter": bool(status_flags & 0b00100000),
                "read-only": bool(status_flags & 0b00010000)
            }

            format_flags = self.buf.ru8()
            frame["format-flags"] = {
                "raw": format_flags,
                "is-grouped": bool(format_flags & 0b01000000),
                "is-compressed": bool(format_flags & 0b00001000),
                "is-encrypted": bool(format_flags & 0b00000100),
                "is-unsynchronized": bool(format_flags & 0b00000010),
                "has-data-length-indictator": bool(format_flags & 0b00000001)
            }

            if frame["format-flags"]["is-grouped"]:
                frame["format-flags"]["group-id"] = self.buf.ru8()

            if frame["format-flags"]["has-data-length-indictator"]:
                frame["format-flags"]["data-length"] = self.read_length(
                    bool(format_flags & 0b00000010))

            content = self.buf.read(frame["length"])

            if frame["format-flags"]["is-unsynchronized"]:
                content = content.replace(b"\xff\x00", b"\xff")

            if frame["format-flags"]["is-encrypted"]:
                frame["data"] = content.hex()
                frame["encrypted"] = True
            else:
                if frame["format-flags"]["is-compressed"]:
                    content = zlib.decompress(content)

                match frame["type"]:
                    case "PRIV":
                        frame["data"] = utils.decode(content).split("\x00")
                    case "APIC":
                        encoding = {
                            0: "latin-1",
                            1: "utf-16",
                            2: "utf-16be",
                            3: "utf-8"
                        }.get(content[0])
                        content = content[1:]

                        mime_type = b""
                        while True:
                            if content[0] == 0:
                                if "16" in encoding and content[1] == 0:
                                    content = content[2:]
                                    break
                                else:
                                    content = content[1:]
                                    break

                            mime_type += content[:2 if "16" in encoding else 1]
                            content = content[2 if "16" in encoding else 1:]

                        frame["data"] = {}
                        frame["data"]["encoding"] = encoding
                        frame["data"]["mime-type"] = mime_type.decode(encoding)
                        frame["data"]["image-type"] = utils.unraw(
                            content[0], 1, {
                                0x00: "Other",
                                0x01: "32x32 pixels file icon PNG only",
                                0x02: "Other file icon",
                                0x03: "Cover front",
                                0x04: "Cover back",
                                0x05: "Leaflet page",
                                0x06: "Media e.g. label side of CD",
                                0x07: "Lead artist/lead performer/soloist",
                                0x08: "Artist/performer",
                                0x09: "Conductor",
                                0x0a: "Band/Orchestra",
                                0x0b: "Composer",
                                0x0c: "Lyricist/text writer",
                                0x0d: "Recording Location",
                                0x0e: "During recording",
                                0x0f: "During performance",
                                0x10: "Movie/video screen capture",
                                0x11: "A bright coloured fish",
                                0x12: "Illustration",
                                0x13: "Band/artist logotype",
                                0x14: "Publisher/Studio logotype"
                            })
                        content = content[1:]

                        desc = b""
                        while True:
                            if content[0] == 0:
                                if "16" in encoding and content[1] == 0:
                                    content = content[2:]
                                    break
                                else:
                                    content = content[1:]
                                    break

                            desc += content[:2 if "16" in encoding else 1]
                            content = content[2 if "16" in encoding else 1:]

                        frame["data"]["description"] = desc.decode(encoding)
                        frame["data"]["image"] = chew(content)
                    case "COMM":
                        encoding = {
                            0: "latin-1",
                            1: "utf-16",
                            2: "utf-16be",
                            3: "utf-8"
                        }.get(content[0])
                        content = content[1:]

                        language = content[:3].decode("latin-1").rstrip("\x00")
                        content = content[3:]

                        short_description = b""
                        while True:
                            if content[0] == 0:
                                if "16" in encoding and content[1] == 0:
                                    content = content[2:]
                                    break
                                else:
                                    content = content[1:]
                                    break

                            short_description += content[:2 if "16" in
                                                         encoding else 1]
                            content = content[2 if "16" in encoding else 1:]

                        frame["data"] = {}
                        frame["data"]["encoding"] = encoding
                        frame["data"]["language"] = language
                        frame["data"][
                            "short-description"] = short_description.decode(
                                encoding)
                        frame["data"]["text"] = content.decode(
                            encoding).rstrip("\x00")
                    case "GEOB":
                        encoding = {
                            0: "latin-1",
                            1: "utf-16",
                            2: "utf-16be",
                            3: "utf-8"
                        }.get(content[0])
                        content = content[1:]

                        mime_type = b""
                        while content[0]:
                            mime_type += content[0:1]
                            content = content[1:]
                        content = content[1:]

                        file_name = b""
                        while True:
                            if content[0] == 0:
                                if "16" in encoding and content[1] == 0:
                                    content = content[2:]
                                    break
                                else:
                                    content = content[1:]
                                    break

                            file_name += content[:2 if "16" in encoding else 1]
                            content = content[2 if "16" in encoding else 1:]

                        description = b""
                        while True:
                            if content[0] == 0:
                                if "16" in encoding and content[1] == 0:
                                    content = content[2:]
                                    break
                                else:
                                    content = content[1:]
                                    break

                            description += content[:2 if "16" in
                                                   encoding else 1]
                            content = content[2 if "16" in encoding else 1:]

                        frame["data"] = {}
                        frame["data"]["encoding"] = encoding
                        frame["data"]["mime-type"] = mime_type.decode(
                            "latin-1")
                        frame["data"]["file-name"] = file_name.decode(encoding)
                        frame["data"]["description"] = description.decode(
                            encoding)
                        frame["data"]["blob"] = chew(content)
                    case "TALB" | "TIT1" | "TIT2" | "TIT3" | "TYER" | "TXXX" | "TPE1" | "TSSE" | "TCOM" | "TPUB" | "TOPE" | "TOAL" | "TCON" | "TPE2" | "TENC" | "TBPM" | "TRCK" | "TDEN" | "TDTG" | "TOFN":
                        frame["data"] = {}
                        frame["data"]["encoding"] = {
                            0: "latin-1",
                            1: "utf-16",
                            2: "utf-16be",
                            3: "utf-8"
                        }.get(content[0])
                        frame["data"]["string"] = content[1:].decode(
                            frame["data"]["encoding"]).rstrip("\x00")

                        if frame["type"] == "TXXX":
                            frame["data"]["namespace"] = frame["data"][
                                "string"].split("\x00")[0]
                            frame["data"]["string"] = frame["data"][
                                "string"].split("\x00")[1]

                            match frame["data"]["namespace"]:
                                case "segmentmetadata":
                                    frame["data"]["string"] = json.loads(
                                        frame["data"]["string"])
                    case _:
                        frame["data"] = content.hex()
                        frame["unknown"] = True

            meta["frames"].append(frame)

        self.buf.skipunit()
        self.buf.popunit()

        if meta["header"]["flags"]["has-footer"]:
            self.buf.skip(10)

        return meta

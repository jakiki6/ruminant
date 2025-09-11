from . import chew
from .. import module, utils, constants

import tempfile


@module.register
class ZipModule(module.RuminantModule):

    def identify(buf, ctx):
        return buf.peek(4) == b"\x50\x4b\x03\x04"

    def chew(self):
        meta = {}
        meta["type"] = "zip"

        self.buf.search(b"\x50\x4b\x05\x06")

        self.buf.skip(4)
        meta["eocd"] = {}
        meta["eocd"]["disc-count"] = self.buf.ru16l()
        meta["eocd"]["central-directory-first-disk"] = self.buf.ru16l()
        meta["eocd"]["central-directory-local-count"] = self.buf.ru16l()
        meta["eocd"]["central-directory-global-count"] = self.buf.ru16l()
        meta["eocd"]["central-directory-size"] = self.buf.ru32l()
        meta["eocd"]["central-directory-offset"] = self.buf.ru32l()
        meta["eocd"]["comment"] = self.buf.rs(self.buf.ru16l())
        eof = self.buf.tell()

        self.buf.seek(meta["eocd"]["central-directory-offset"])

        meta["files"] = []
        while self.buf.pu32() == 0x504b0102:
            self.buf.skip(4)

            file = {}
            file["meta"] = {}
            file["meta"]["version-producer"] = self.buf.ru16l()
            file["meta"]["version-needed"] = self.buf.ru16l()
            file["meta"]["general-flags"] = self.buf.rh(2)
            file["meta"]["compression-method"] = self.buf.ru16l()
            file["meta"]["modification-time"] = self.buf.ru16l()
            file["meta"]["modification-date"] = self.buf.ru16l()
            file["meta"]["crc32"] = self.buf.rh(4)
            file["meta"]["compressed-size"] = self.buf.ru32l()
            file["uncompressed-size"] = self.buf.ru32l()
            filename_length = self.buf.ru16l()
            extra_field_length = self.buf.ru16l()
            comment_length = self.buf.ru16l()
            file["meta"]["start-disk"] = self.buf.ru16l()
            file["meta"]["internal-attributes"] = self.buf.rh(2)
            file["meta"]["external-attributes"] = self.buf.rh(4)
            file["offset"] = self.buf.ru32l()
            file["filename"] = self.buf.rs(filename_length)
            file["meta"]["extra-field"] = self.buf.rs(extra_field_length,
                                                      "latin-1")
            file["meta"]["comment"] = self.buf.rs(comment_length)

            if file["uncompressed-size"] > 0:
                with self.buf:
                    self.buf.seek(file["offset"])
                    assert self.buf.ru32() == 0x504b0304, "broken ZIP file"
                    self.buf.skip(22)
                    self.buf.skip(self.buf.ru16l() + self.buf.ru16l())

                    match file["meta"]["compression-method"]:
                        case 0:
                            with self.buf.sub(file["uncompressed-size"]):
                                file["data"] = chew(self.buf)

                        case 8:
                            with self.buf.sub(file["meta"]["compressed-size"]):
                                fd = tempfile.TemporaryFile()
                                utils.stream_deflate(self.buf, fd,
                                                     self.buf.available())
                                fd.seek(0)

                                file["data"] = chew(fd)

            meta["files"].append(file)

        self.buf.seek(eof)
        return meta


@module.register
class RIFFModule(module.RuminantModule):

    def identify(buf, ctx):
        return buf.peek(4) in (b"RIFF", b"AT&T")

    def chew(self):
        meta = {}
        meta["type"] = {b"RIFF": "riff", b"AT&T": "djvu"}[self.buf.peek(4)]

        if meta["type"] == "djvu":
            self.buf.skip(4)
            self.le = False
        else:
            self.le = True

        self.strh_type = None
        meta["data"] = self.read_chunk()

        return meta

    def read_chunk(self):
        chunk = {}

        typ = self.buf.rs(4)
        chunk["type"] = typ
        chunk["offset"] = self.buf.tell() - 4
        length = self.buf.ru32l() if self.le else self.buf.ru32()
        chunk["length"] = length

        self.buf.pushunit()
        self.buf.setunit(((length + 1) >> 1) << 1)

        chunk["data"] = {}
        match typ:
            case "VP8 ":
                tag = self.buf.ru24()
                chunk["data"]["keyframe"] = bool(tag & 0x800000)
                chunk["data"]["version"] = (tag >> 20) & 0x07
                chunk["data"]["show-frame"] = bool(tag & 0x80000)
                chunk["data"]["partition-size"] = tag & 0x7ffff
                chunk["data"]["start-code"] = self.buf.rh(3)
                chunk["data"]["width"] = self.buf.ru16l() & 0x3fff
                chunk["data"]["height"] = self.buf.ru16l() & 0x3fff
            case "VP8L":
                chunk["data"]["signature"] = self.buf.rh(1)
                tag = self.buf.ru32l()
                for field in ("width", "height"):
                    i = 1
                    for j in range(0, 14):
                        i += (tag & 1) << j
                        tag >>= 1

                    chunk["data"][field] = i

                chunk["data"]["has-alpha"] = bool(tag & 1)
                chunk["data"]["version"] = ((tag >> 1) & 1) | ((
                    (tag >> 2) & 1) << 1) | (((tag >> 3) & 1) << 2)
            case "ANIM":
                chunk["data"]["background-color"] = {
                    "red": self.buf.ru8(),
                    "green": self.buf.ru8(),
                    "blue": self.buf.ru8(),
                    "alpha": self.buf.ru8()
                }
                chunk["data"]["loop-count"] = self.buf.ru16l()
            case "ANMF":
                chunk["data"]["frame-x"] = self.buf.ru24l()
                chunk["data"]["frame-y"] = self.buf.ru24l()
                chunk["data"]["frame-width"] = self.buf.ru24l() + 1
                chunk["data"]["frame-height"] = self.buf.ru24l() + 1
                chunk["data"]["frame-duration"] = self.buf.ru24l()

                tag = self.buf.ru8()
                chunk["data"]["reserved"] = tag >> 2
                chunk["data"]["alpha-blend"] = not bool(tag & 2)
                chunk["data"]["dispose"] = bool(tag & 1)
            case "ALPH":
                tag = self.buf.ru8()
                chunk["data"]["reserved"] = tag >> 6
                chunk["data"]["preprocessing"] = (tag >> 4) & 0x03
                chunk["data"]["filtering-method"] = (tag >> 2) & 0x03
                chunk["data"]["compression-method"] = tag & 0x03
            case "VP8X":
                tag = self.buf.ru32()
                chunk["data"]["reserved1"] = tag >> 30
                chunk["data"]["has-icc-profile"] = bool(tag & (1 << 29))
                chunk["data"]["has-alpha"] = bool(tag & (1 << 28))
                chunk["data"]["has-exif"] = bool(tag & (1 << 27))
                chunk["data"]["has-xmp"] = bool(tag & (1 << 26))
                chunk["data"]["has-animation"] = bool(tag & (1 << 25))
                chunk["data"]["reserved2"] = tag & 0x1ffffff
                chunk["data"]["width"] = self.buf.ru24l() + 1
                chunk["data"]["height"] = self.buf.ru24l() + 1
            case "fmt ":
                chunk["data"]["format"] = self.buf.ru16l()
                chunk["data"]["channel-count"] = self.buf.ru16l()
                chunk["data"]["sample-rate"] = self.buf.ru32l()
                chunk["data"]["byte-rate"] = self.buf.ru32l()
                chunk["data"]["block-align"] = self.buf.ru16l()
                chunk["data"]["bits-per-sample"] = self.buf.ru16l()
            case "ICCP":
                with self.buf.subunit():
                    chunk["data"]["color-profile"] = chew(self.buf)
            case "avih":
                chunk["data"]["microseconds-per-frame"] = self.buf.ru32l()
                chunk["data"]["max-bytes-per-second"] = self.buf.ru32l()
                chunk["data"]["padding-granularity"] = self.buf.ru32l()
                chunk["data"]["flags"] = self.buf.rh(4)
                chunk["data"]["frame-count"] = self.buf.ru32l()
                chunk["data"]["initial-frames"] = self.buf.ru32l()
                chunk["data"]["stream-count"] = self.buf.ru32l()
                chunk["data"]["buffer-size"] = self.buf.ru32l()
                chunk["data"]["width"] = self.buf.ru32l()
                chunk["data"]["height"] = self.buf.ru32l()
                chunk["data"]["reserved"] = self.buf.rh(16)

                chunk["data"]["derived"] = {}
                chunk["data"]["derived"][
                    "fps"] = 1000000 / chunk["data"]["microseconds-per-frame"]
                chunk["data"]["derived"]["duration-in-seconds"] = chunk[
                    "data"]["frame-count"] * chunk["data"][
                        "microseconds-per-frame"] / 1000000
            case "strh":
                self.strh_type = self.buf.rs(4)
                chunk["data"]["type"] = self.strh_type
                chunk["data"]["handler"] = self.buf.rs(4)
                chunk["data"]["flags"] = self.buf.rh(4)
                chunk["data"]["priority"] = self.buf.ru16l()

                language = self.buf.ru16l()
                chunk["data"]["language"] = {
                    "raw": language,
                    "name": constants.MICROSOFT_LCIDS.get(language, "Unknown")
                }

                chunk["data"]["initial-frames"] = self.buf.ru32l()
                chunk["data"]["scale"] = self.buf.ru32l()
                chunk["data"]["rate"] = self.buf.ru32l()
                chunk["data"]["start"] = self.buf.ru32l()
                chunk["data"]["length"] = self.buf.ru32l()
                chunk["data"]["buffer-size"] = self.buf.ru32l()
                chunk["data"]["quality"] = self.buf.ri32l()
                chunk["data"]["sample-size"] = self.buf.ru32l()
                chunk["data"]["frame-left"] = self.buf.ru16l()
                chunk["data"]["frame-top"] = self.buf.ru16l()
                chunk["data"]["frame-right"] = self.buf.ru16l()
                chunk["data"]["frame-bottom"] = self.buf.ru16l()
            case "strf":
                match self.strh_type:
                    case "vids":
                        chunk["data"]["header-size"] = self.buf.ru32l()
                        chunk["data"]["width"] = self.buf.ru32l()
                        chunk["data"]["height"] = self.buf.ru32l()
                        chunk["data"]["plane-count"] = self.buf.ru16l()
                        chunk["data"]["bits-per-pixel"] = self.buf.ru16l()
                        chunk["data"]["compression-method"] = self.buf.rs(4)
                        chunk["data"]["image-size"] = self.buf.ru32l()
                        chunk["data"][
                            "horizontal-resolution"] = self.buf.ru32l()
                        chunk["data"]["vertical-resolution"] = self.buf.ru32l()
                        chunk["data"]["used-color-count"] = self.buf.ru32l()
                        chunk["data"][
                            "important-color-count"] = self.buf.ru32l()
                    case "auds":
                        format_tag = self.buf.ru16l()
                        chunk["data"]["format"] = {
                            "raw": format_tag,
                            "name": {
                                0x0001: "PCM",
                                0x0050: "MPEG",
                                0x2000: "AC-3",
                                0x00ff: "AAC",
                                0x0161: "WMA",
                                0x2001: "DTS",
                                0xf1ac: "FLAC"
                            }.get(format_tag, "Unknown")
                        }

                        chunk["data"]["channel-count"] = self.buf.ru16l()
                        chunk["data"]["sample-rate"] = self.buf.ru32l()
                        chunk["data"][
                            "average-bytes-per-second"] = self.buf.ru32l()
                        chunk["data"]["block-alignment"] = self.buf.ru16l()
                        chunk["data"]["bits-per-sample"] = self.buf.ru16l()

                        codec_data_size = self.buf.ru16l()
                        chunk["data"]["codec-data-size"] = codec_data_size
                    case _:
                        chunk["data"]["unknown-type"] = True

                self.strh_type = None
            case "vprp":
                chunk["data"]["format"] = self.buf.rs(4)

                standard = self.buf.ru32l()
                chunk["data"]["standard"] = {
                    "raw": standard,
                    "name": {
                        0: "NTSC",
                        1: "PAL",
                        2: "SECAM"
                    }.get(standard, "Unknown")
                }

                chunk["data"]["vertical-refresh-rate"] = self.buf.ru32l()
                chunk["data"]["horizontal-total"] = self.buf.ru32l()
                chunk["data"]["vertical-total"] = self.buf.ru32l()

                y, x = self.buf.ru16l(), self.buf.ru16l()
                chunk["data"]["aspect-ratio"] = f"{x}:{y}"

                chunk["data"]["width"] = self.buf.ru32l()
                chunk["data"]["height"] = self.buf.ru32l()

                field_count = self.buf.ru32l()
                chunk["data"]["field-count"] = field_count

                chunk["data"]["fields"] = []
                for i in range(0, field_count):
                    field = {}
                    field["compressed-width"] = self.buf.ru32l()
                    field["compressed-height"] = self.buf.ru32l()
                    field["valid-width"] = self.buf.ru32l()
                    field["valid-height"] = self.buf.ru32l()
                    field["valid-x-offset"] = self.buf.ru32l()
                    field["valid-y-offset"] = self.buf.ru32l()

                    chunk["data"]["fields"].append(field)
            case "INFO":
                chunk["data"]["width"] = self.buf.ru16()
                chunk["data"]["height"] = self.buf.ru16()
                chunk["data"]["minor-version"] = self.buf.ru8()
                chunk["data"]["major-version"] = self.buf.ru8()
                chunk["data"]["dpi"] = self.buf.ru16()
                chunk["data"]["gamma"] = self.buf.ru8() / 10

                flags = self.buf.ru8()
                chunk["data"]["flags"] = {
                    "raw": flags,
                    "rotation": {
                        1: "0 degrees",
                        6: "90 degrees counter clockwise",
                        2: "180 degrees",
                        5: "90 degrees clockwise"
                    }.get(flags & 0x07, f"Unknown ({flags & 0x07})")
                }
            case "INCL":
                chunk["data"]["id"] = utils.decode(
                    self.buf.readunit()).rstrip("\x00")
            case "fact":
                chunk["data"]["sample-count"] = self.buf.ru32l()
            case "cue ":
                chunk["data"]["cues"] = []

                for i in range(0, self.buf.ru32l()):
                    cue = {}
                    cue["id"] = self.buf.ru32l()
                    cue["position"] = self.buf.ru32l()
                    cue["data-chunk-id"] = self.buf.rs(4)
                    cue["chunk-start"] = self.buf.ru32l()
                    cue["block-start"] = self.buf.ru32l()
                    cue["sample-offset"] = self.buf.ru32l()

                    chunk["data"]["cues"].append(cue)
            case "labl":
                chunk["data"]["cue-id"] = self.buf.ru32l()
                chunk["data"]["label"] = self.buf.rzs()
            case "bext":
                chunk["data"]["description"] = self.buf.rs(256)
                chunk["data"]["originator"] = self.buf.rs(32)
                chunk["data"]["originator-ref"] = self.buf.rs(32)
                chunk["data"]["originator-date"] = self.buf.rs(10)
                chunk["data"]["originator-time"] = self.buf.rs(8)
                chunk["data"]["time-reference"] = self.buf.ru64l()
                chunk["data"]["version"] = self.buf.ru16l()

                if sum(self.buf.peek(64)):
                    chunk["data"]["umid"] = self.buf.rh(64)
                else:
                    self.buf.skip(64)

                if sum(self.buf.peek(190)):
                    chunk["data"]["reserved"] = self.buf.rh(190)
                else:
                    self.buf.skip(190)

                chunk["data"]["coding-history"] = utils.decode(
                    self.buf.readunit()).rstrip("\x00")
            case "iXML":
                chunk["data"]["xml"] = utils.xml_to_dict(self.buf.readunit())
            case "ID3 ":
                with self.buf.subunit():
                    chunk["data"]["id3-tag"] = chew(self.buf)
            case "SNDM":
                chunk["data"]["entries"] = []

                while self.buf.unit >= 12:
                    entry = {}
                    length = self.buf.ru32()
                    entry["key"] = self.buf.rs(4)
                    self.buf.skip(4)
                    entry["value"] = self.buf.rs(length - 12)

                    chunk["data"]["entries"].append(entry)
            case "PAD " | "FLLR" | "filr" | "regn":
                content = self.buf.readunit()

                chunk["data"]["non-zero"] = bool(sum(content))

                if chunk["data"]["non-zero"]:
                    chunk["data"]["data"] = chew(content)
            case "EXIF":
                with self.buf.subunit():
                    chunk["data"]["exif"] = chew(self.buf)
            case "XMP ":
                with self.buf.subunit():
                    chunk["data"]["xmp"] = utils.xml_to_dict(
                        self.buf.readunit())
            case "ICMT" | "ISFT" | "INAM" | "IART" | "ICRD" | "IARL" | "ILNG" | "IMED" | "ISRC" | "ISRF" | "ITCH" | "strn":
                chunk["data"]["text"] = utils.decode(
                    self.buf.readunit()).rstrip("\x00")
            case "RIFF" | "LIST" | "FORM":
                chunk["data"]["type"] = self.buf.rs(4)

                if chunk["data"]["type"] != "movi":
                    chunk["data"]["chunks"] = []

                    while self.buf.unit:
                        list_chunk = self.read_chunk()
                        chunk["data"]["chunks"].append(list_chunk)
            case "data" | "JUNK" | "idx1" | "indx" | "ix00" | "ix01":
                pass
            case _:
                chunk["data"]["unknown"] = True

                with self.buf.subunit():
                    chunk["data"]["blob"] = chew(self.buf)

        self.buf.skipunit()
        self.buf.popunit()

        return chunk


@module.register
class TarModule(module.RuminantModule):

    def identify(buf, ctx):
        return buf.peek(262)[257:] == b"ustar"

    def chew(self):
        meta = {}
        meta["type"] = "tar"

        meta["name"] = self.buf.rs(100).rstrip(" ").rstrip("\x00")
        meta["mode"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")
        meta["owner-uid"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")
        meta["owner-gid"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")

        file_length = self.buf.rs(12).rstrip(" ").rstrip("\x00")
        meta["size"] = file_length

        meta["modification-date"] = self.buf.rs(12).rstrip(" ").rstrip("\x00")
        meta["checksum"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")
        meta["file-type"] = utils.unraw(
            self.buf.ru8(), 1, {
                0: "Normal file",
                ord("0"): "Normal file",
                ord("1"): "Hard link",
                ord("2"): "Soft link",
                ord("3"): "Character special",
                ord("4"): "Block special",
                ord("5"): "Directory",
                ord("6"): "FIFO",
                ord("7"): "Contiguous file",
                ord("g"): "Global pax header",
                ord("x"): "Local pax header"
            })

        meta["link-name"] = self.buf.rs(100).rstrip(" ").rstrip("\x00")

        self.buf.skip(6)

        meta["ustar-version"] = self.buf.rs(2).rstrip(" ").rstrip("\x00")
        meta["owner-user-name"] = self.buf.rs(32).rstrip(" ").rstrip("\x00")
        meta["owner-group-name"] = self.buf.rs(32).rstrip(" ").rstrip("\x00")
        meta["device-major"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")
        meta["device-minor"] = self.buf.rs(8).rstrip(" ").rstrip("\x00")
        meta["name"] = self.buf.rs(155).rstrip(" ").rstrip(
            "\x00") + meta["name"]

        self.buf.skip(12)

        file_length = int(file_length, 8)

        if file_length > 0:
            self.buf.pushunit()
            self.buf.setunit(file_length)

            with self.buf.subunit():
                if meta["file-type"]["raw"] == ord("x"):
                    meta["data"] = self.buf.readunit().decode("utf-8")
                else:
                    meta["data"] = chew(self.buf)

            self.buf.skipunit()
            self.buf.popunit()

            if file_length % 512:
                self.buf.skip(512 - (file_length % 512))

        return meta

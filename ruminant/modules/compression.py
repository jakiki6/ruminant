from .. import module, utils
from . import chew

import datetime
import tempfile
import zlib
import math
import sys


@module.register
class GzipModule(module.RuminantModule):
    desc = "gzip steams."

    def identify(buf, ctx):
        return buf.peek(2) == b"\x1f\x8b"

    def chew(self):
        meta = {}
        meta["type"] = "gzip"

        self.buf.skip(2)

        compression_method = self.buf.ru8()
        assert compression_method == 8, f"Unknown gzip compression method {compression_method}"
        meta["compression-method"] = utils.unraw(compression_method, 2,
                                                 {8: "Deflate"})

        flags = self.buf.ru8()
        meta["flags"] = {
            "raw": flags,
            "is-probably-text": bool(flags & 0x01),
            "has-crc": bool(flags & 0x02),
            "has-extra": bool(flags & 0x04),
            "has-name": bool(flags & 0x08),
            "has-comment": bool(flags & 0x10),
            "reserved": flags >> 5
        }

        meta["time"] = datetime.datetime.utcfromtimestamp(
            self.buf.ru32l()).isoformat()
        meta["extra-flags"] = utils.unraw(
            self.buf.ru8(), 2, {
                0: "None",
                2: "Best compression (level 9)",
                4: "Fastest compression (level 1)"
            })
        meta["filesystem"] = utils.unraw(
            self.buf.ru8(), 2, {
                0: "FAT",
                1: "Amiga",
                2: "OpenVMS",
                3: "Unix",
                4: "VM/CMS",
                5: "Atari TOS",
                6: "HPFS",
                7: "Macintosh",
                8: "Z-System",
                9: "CP/M",
                10: "TOPS-20",
                11: "NTFS",
                12: "QDOS",
                13: "RISCOS",
                255: "None"
            })

        if flags & 0x04:
            self.buf.pushunit()
            self.buf.setunit(self.buf.ru16l())

            meta["extra"] = []
            while self.buf.unit > 0:
                extra = {}
                extra["type"] = self.buf.rs(2, "latin-1")
                extra["content"] = utils.decode(self.buf.read(
                    self.buf.ru16l()))
                meta["extra"].append(extra)

            self.buf.skipunit()
            self.buf.popunit()

        if flags & 0x08:
            meta["name"] = self.buf.rzs("latin-1")

        if flags & 0x10:
            meta["comment"] = self.buf.rzs("latin-1")

        if flags & 0x02:
            meta["header-crc"] = self.buf.rh(2)

        meta["footer-crc"] = None
        meta["size-mod-2^32"] = None

        self.buf.unit = None
        with tempfile.TemporaryFile() as fd:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

            while not decompressor.eof:
                fd.write(
                    decompressor.decompress(
                        self.buf.read(min(1 << 24, self.buf.available()))))

            self.buf.seek(-len(decompressor.unused_data), 1)

            fd.write(decompressor.flush())

            fd.seek(0)
            meta["data"] = chew(fd)

        if self.buf.available() >= 4:
            meta["footer-crc"] = self.buf.rh(4)
        if self.buf.available() >= 4:
            meta["size-mod-2^32"] = self.buf.ru32l()

        return meta


@module.register
class Bzip2Module(module.RuminantModule):
    desc = "bzip2 streams."

    def identify(buf, ctx):
        return buf.peek(2) == b"BZ"

    def chew(self):
        meta = {}
        meta["type"] = "bzip2"

        with self.buf:
            offset = self.buf.tell()

            self.buf.search(b"\x17\x72\x45\x38\x50\x90")
            length = self.buf.tell() - offset

        with tempfile.TemporaryFile() as fd:
            utils.stream_bzip2(self.buf, fd, length)

            fd.seek(0)
            meta["data"] = chew(fd)

        return meta


@module.register
class ZstdModule(module.RuminantModule):
    desc = "Zstandard streams.\nIdeally, you should install pyzstd or backports.zstd or run Python version 3.14 or higher to allow decompression of the content."

    def identify(buf, ctx):
        return buf.peek(4) == b"\x28\xb5\x2f\xfd"

    def chew(self):
        meta = {}
        meta["type"] = "zstd"

        has_zstd = True
        try:
            import pyzstd as zstd
        except ImportError:
            try:
                if sys.version_info >= (3, 14):
                    from compression import zstd
                else:
                    from backports import zstd
            except ImportError:
                has_zstd = False

        with self.buf:
            self.buf.skip(4)
            meta["header"] = {}
            meta["header"]["flags"] = {"raw": self.buf.ru8(), "names": []}

            meta["header"]["flags"]["names"].append(
                ["FCS_1", "FCS_2", "FCS_4",
                 "FCS_8"][meta["header"]["flags"]["raw"] >> 6])
            if meta["header"]["flags"]["raw"] & (1 << 5):
                meta["header"]["flags"]["names"].append("SINGLE_SEGMENT")
                if "FCS_1" in meta["header"]["flags"]["names"]:
                    meta["header"]["flags"]["names"].remove("FCS_1")
            if meta["header"]["flags"]["raw"] & (1 << 2):
                meta["header"]["flags"]["names"].append("CONTENT_CHECKSUM")
            if meta["header"]["flags"]["raw"] & 0x03:
                meta["header"]["flags"]["names"].append(
                    [None, "DID_1", "DID_2",
                     "DID_4"][meta["header"]["flags"]["raw"] & 0x03])

            if "SINGLE_SEGMENT" not in meta["header"]["flags"]["names"]:
                temp = self.buf.ru8()
                exponent = temp >> 3
                mantissa = temp & 0x03
                meta["header"]["window-size"] = math.ceil(
                    ((1 << (exponent + 10)) / 8) * mantissa +
                    (1 << (exponent + 10)))

            if "DID_1" in meta["header"]["flags"]["names"]:
                meta["header"]["dictionary-id"] = self.buf.ru8()
            elif "DID_2" in meta["header"]["flags"]["names"]:
                meta["header"]["dictionary-id"] = self.buf.ru16l()
            elif "DID_4" in meta["header"]["flags"]["names"]:
                meta["header"]["dictionary-id"] = self.buf.ru32l()

            if "FCS_1" in meta["header"]["flags"]["names"]:
                meta["header"]["frame-content-size"] = self.buf.ru8()
            elif "FCS_2" in meta["header"]["flags"]["names"]:
                meta["header"]["frame-content-size"] = self.buf.ru16l()
            elif "FCS_4" in meta["header"]["flags"]["names"]:
                meta["header"]["frame-content-size"] = self.buf.ru32l()
            elif "FCS_8" in meta["header"]["flags"]["names"]:
                meta["header"]["frame-content-size"] = self.buf.ru64l()

            base = self.buf.tell()

        self.buf.seek(base)
        while True:
            header = self.buf.ru24l()
            last = header & 0x01
            typ = (header >> 1) & 0x03
            length = header >> 3

            if typ == 0 or typ == 2:
                self.buf.skip(length)
            else:
                self.buf.skip(1)

            if last:
                break

        if "CONTENT_CHECKSUM" in meta["header"]["flags"]["names"]:
            self.buf.skip(4)

        if has_zstd:
            offset = self.buf.tell()

            with self.buf:
                self.buf.seek(0)

                decompressor = zstd.ZstdDecompressor()
                fd = utils.tempfd()
                utils.stream_generic(decompressor, self.buf, fd, offset)

                fd.seek(0)
                meta["data"] = chew(fd)

        return meta


@module.register
class ZlibModule(module.RuminantModule):
    desc = "zlib streams."

    def identify(buf, ctx):
        return buf.peek(2) in (b"\x78\x01", b"\x78\x9c", b"\x78\xda")

    def chew(self):
        meta = {}
        meta["type"] = "zlib"

        fd = utils.tempfd()
        utils.stream_zlib(self.buf, fd, self.buf.available())
        fd.seek(0)
        meta["data"] = chew(fd)

        return meta

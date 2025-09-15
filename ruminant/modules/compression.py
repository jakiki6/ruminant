from .. import module, utils
from . import chew

import datetime
import tempfile
import zlib


@module.register
class GzipModule(module.RuminantModule):

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
                13: "RISCOS"
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

        meta["footer-crc"] = self.buf.rh(4)
        meta["size-mod-2^32"] = self.buf.ru32l()

        return meta


@module.register
class Bzip2Module(module.RuminantModule):

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

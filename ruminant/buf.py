import io
import struct
import uuid


def _decode(content, encoding="utf-8"):
    try:
        return content.decode(encoding)
    except Exception:
        return content.decode("latin-1")


class Buf(object):

    def __init__(self, source):
        if isinstance(source, io.IOBase):
            self._file = source
        else:
            self._file = io.BytesIO(source)

        self._offset = 0

        pos = self.tell()
        self.seek(0, 2)
        self._size = self.tell()
        self.seek(pos)

        self.resetunit()
        self._target = self._size
        self._stack = []
        self._backup = []

    @classmethod
    def of(cls, source):
        if isinstance(source, cls):
            return source
        else:
            return cls(source)

    def available(self):
        return max(self._size - self.tell(), 0)

    def isend(self):
        return self.available() <= 0

    def size(self):
        return self._size

    def peek(self, length):
        pos = self.tell()
        data = self._file.read(length)
        self.seek(pos)
        return data

    def skip(self, length):
        if self.unit is not None:
            self.unit = max(self.unit - length, 0)
            assert (
                self.unit >= 0
            ), f"unit overread by {-self.unit} byte{'s' if self.unit != -1 else ''}"
        self.seek(length, 1)

    def _checkunit(self):
        assert (
            self.unit >= 0
        ), f"unit overread by {-self.unit} byte{'s' if self.unit != -1 else ''}"

    def setunit(self, length):
        self.unit = length
        self._target = self.tell() + length
        self._checkunit()

    def skipunit(self):
        self.seek(self._target)
        self.unit = 0

    def readunit(self):
        return self.read(self.unit)

    def resetunit(self):
        self.unit = None

    def read(self, count=None):
        if count is None:
            self.unit = None
            return self._file.read(self.available())
        else:
            if self.unit is not None:
                self.unit -= count
                self._checkunit()

            if self.available() < count:
                self.unit = self.available() - count
                self._checkunit()

            return self._file.read(count)

    def pushunit(self):
        self._stack.append((self.unit, self._target))

    def popunit(self):
        self.unit, t = self._stack.pop()
        if self.unit is not None:
            self.unit = max(t - self._target, 0)
        self._target = t

    def backup(self):
        return (self.unit, self._target, self._stack, self.tell())

    def restore(self, bak):
        self.unit, self._target, self._stack, offset = bak
        self.seek(offset)

    def rl(self):
        line = b""
        while (self.unit is None or (self.unit > 0)) and self.available() > 0:
            c = self.read(1)
            if len(c) == 0:
                break

            if c[0] in (0x0a, 0x0d):
                if self.peek(1) != b"" and self.peek(1)[0] in (
                        0x0a, 0x0d) and self.peek(1) != c:
                    self.skip(1)
                break

            line += c

        return line

    def tell(self):
        return self._file.tell() - self._offset

    def seek(self, pos, whence=0):
        if whence == 0:
            pos += self._offset

        self._file.seek(pos, whence)

    def sub(self, size):
        assert size <= self.size(), "sub buffer is bigger than host buffer"

        class SubWrapper(object):

            def __enter__(self2):
                self2._offset = self._offset
                self2._size = self._size
                self2._bak = self.backup()
                self._offset += self.tell()
                self._size = size

            def __exit__(self2, *args):
                self._offset = self2._offset
                self._size = self2._size
                self.restore(self2._bak)

        return SubWrapper()

    def subunit(self):
        return self.sub(self.unit)

    def cut(self):
        return self.sub(self.available())

    def search(self, s, buf_length=1 << 24):
        buf = b""
        while True:
            chunk = self.read(
                min(buf_length, self.unit if self.unit else self.available()))
            buf += chunk

            if (self.unit is not None and self.unit <= 0) or len(chunk) == 0:
                raise ValueError(f"pattern {s.hex()} not found")

            if s not in buf:
                buf = buf[-len(s):]
            else:
                index = buf.index(s)
                overread = len(buf) - index
                if self.unit is not None:
                    self.unit += overread
                self.seek(-overread, 1)
                return

    def ru8(self):
        return int.from_bytes(self.read(1), "big")

    def ru16(self):
        return int.from_bytes(self.read(2), "big")

    def ru24(self):
        return int.from_bytes(self.read(3), "big")

    def ru32(self):
        return int.from_bytes(self.read(4), "big")

    def ru64(self):
        return int.from_bytes(self.read(8), "big")

    def ri8(self):
        return int.from_bytes(self.read(1), "big", signed=True)

    def ri16(self):
        return int.from_bytes(self.read(2), "big", signed=True)

    def ri24(self):
        return int.from_bytes(self.read(3), "big", signed=True)

    def ri32(self):
        return int.from_bytes(self.read(4), "big", signed=True)

    def ri64(self):
        return int.from_bytes(self.read(8), "big", signed=True)

    def ru8l(self):
        return int.from_bytes(self.read(1), "little")

    def ru16l(self):
        return int.from_bytes(self.read(2), "little")

    def ru24l(self):
        return int.from_bytes(self.read(3), "little")

    def ru32l(self):
        return int.from_bytes(self.read(4), "little")

    def ru64l(self):
        return int.from_bytes(self.read(8), "little")

    def ri8l(self):
        return int.from_bytes(self.read(1), "little", signed=True)

    def ri16l(self):
        return int.from_bytes(self.read(2), "little", signed=True)

    def ri24l(self):
        return int.from_bytes(self.read(3), "little", signed=True)

    def ri32l(self):
        return int.from_bytes(self.read(4), "little", signed=True)

    def ri64l(self):
        return int.from_bytes(self.read(8), "little", signed=True)

    def rf16(self):
        return struct.unpack(">e", self.read(2))[0]

    def rf32(self):
        return struct.unpack(">f", self.read(4))[0]

    def rf64(self):
        return struct.unpack(">d", self.read(8))[0]

    def rf16l(self):
        return struct.unpack("<e", self.read(2))[0]

    def rf32l(self):
        return struct.unpack("<f", self.read(4))[0]

    def rf64l(self):
        return struct.unpack("<d", self.read(8))[0]

    def rfp16(self):
        return self.ru16() / 256

    def rfp32(self):
        return self.ru32() / 65536

    def rsfp16(self):
        return self.ri16() / 256

    def rsfp32(self):
        return self.ri32() / 65536

    def rfp16l(self):
        return self.ru16l() / 256

    def rfp32l(self):
        return self.ru32l() / 65536

    def rsfp16l(self):
        return self.ri16l() / 256

    def rsfp32l(self):
        return self.ri32l() / 65536

    def pu8(self):
        return int.from_bytes(self.peek(1), "big")

    def pu16(self):
        return int.from_bytes(self.peek(2), "big")

    def pu24(self):
        return int.from_bytes(self.peek(3), "big")

    def pu32(self):
        return int.from_bytes(self.peek(4), "big")

    def pu64(self):
        return int.from_bytes(self.peek(8), "big")

    def pi8(self):
        return int.from_bytes(self.peek(1), "big", signed=True)

    def pi16(self):
        return int.from_bytes(self.peek(2), "big", signed=True)

    def pi24(self):
        return int.from_bytes(self.peek(3), "big", signed=True)

    def pi32(self):
        return int.from_bytes(self.peek(4), "big", signed=True)

    def pi64(self):
        return int.from_bytes(self.peek(8), "big", signed=True)

    def pu8l(self):
        return int.from_bytes(self.peek(1), "little")

    def pu16l(self):
        return int.from_bytes(self.peek(2), "little")

    def pu24l(self):
        return int.from_bytes(self.peek(3), "little")

    def pu32l(self):
        return int.from_bytes(self.peek(4), "little")

    def pu64l(self):
        return int.from_bytes(self.peek(8), "little")

    def pi8l(self):
        return int.from_bytes(self.peek(1), "little", signed=True)

    def pi16l(self):
        return int.from_bytes(self.peek(2), "little", signed=True)

    def pi24l(self):
        return int.from_bytes(self.peek(3), "little", signed=True)

    def pi32l(self):
        return int.from_bytes(self.peek(4), "little", signed=True)

    def pi64l(self):
        return int.from_bytes(self.peek(8), "little", signed=True)

    def pf32(self):
        return struct.unpack(">f", self.peek(4))

    def pf64(self):
        return struct.unpack(">d", self.peek(8))

    def pf32l(self):
        return struct.unpack("<f", self.peek(4))

    def pf64l(self):
        return struct.unpack("<d", self.peek(8))

    def pfp16(self):
        return self.ru16() / 256

    def pfp32(self):
        return self.ru32l() / 65536

    def psfp16(self):
        return self.ri16l() / 256

    def psfp32(self):
        return self.ri32l() / 65536

    def pfp16l(self):
        return self.ru16l() / 256

    def pfp32l(self):
        return self.ru32l() / 65536

    def psfp16l(self):
        return self.ri16l() / 256

    def psfp32l(self):
        return self.ri32l() / 65536

    def rh(self, length):
        return self.read(length).hex()

    def ph(self, length):
        return self.peek(length).hex()

    def rs(self, length, encoding="utf-8", strip=True):
        s = _decode(self.read(length), encoding)
        if strip:
            s = s.rstrip("\x00")
        return s

    def ps(self, length, encoding="utf-8", strip=True):
        s = _decode(self.peek(length), encoding)
        if strip:
            s = s.rstrip("\x00")
        return s

    def rzs(self, encoding="utf-8"):
        s = b""
        while self.pu8():
            s += self.read(1)

        self.skip(1)

        return _decode(s, encoding)

    def pzs(self, encoding="utf-8"):
        pos = self.tell()

        s = b""
        while self.pu8():
            s += self._file.read(1)

        self.seek(pos)

        return _decode(s, encoding)

    def ruuid(self):
        return str(uuid.UUID(bytes=self.read(16)))

    def puuid(self):
        return str(uuid.UUID(bytes=self.peek(16)))

    def ruleb(self):
        c = self.ru8()
        v = c & 0x7f
        shift = 7

        while c & 0x80:
            c = self.ru8()
            v |= (c & 0x7f) << shift
            shift += 7

        return v

    def puleb(self):
        with self.buf:
            return self.ruleb()

    def __getattr__(self, name):
        # Delegate everything else to the underlying file
        return getattr(self._file, name)

    def __enter__(self):
        self._backup.append(self.backup())

    def __exit__(self, *args):
        self.restore(self._backup.pop())

    def __iter__(self):
        return iter(self._file)

    def __next__(self):
        return next(self._file)

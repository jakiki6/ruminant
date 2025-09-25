# taken from https://github.com/joeatwork/python-lzw/blob/master/lzw/__init__.py
# licensed as MIT
# Copyright (c) 2010 Joseph Bowers
# stripped to only contain decompression logic

import struct

CLEAR_CODE = 256
END_OF_INFO_CODE = 257

DEFAULT_MIN_BITS = 9
DEFAULT_MAX_BITS = 12


def decompress(compressed_bytes):
    decoder = ByteDecoder()
    return decoder.decodefrombytes(compressed_bytes)


class ByteDecoder(object):

    def __init__(self):
        """
       """

        self._decoder = Decoder()
        self._unpacker = BitUnpacker(
            initial_code_size=self._decoder.code_size())
        self.remaining = []

    def decodefrombytes(self, bytesource):
        codepoints = self._unpacker.unpack(bytesource)
        clearbytes = self._decoder.decode(codepoints)

        return clearbytes


class BitUnpacker(object):

    def __init__(self, initial_code_size):
        self._initial_code_size = initial_code_size

    def unpack(self, bytesource):
        bits = []
        offset = 0
        ignore = 0

        codesize = self._initial_code_size
        minwidth = 8
        while (1 << minwidth) < codesize:
            minwidth = minwidth + 1

        pointwidth = minwidth

        for nextbit in bytestobits(bytesource):

            offset = (offset + 1) % 8
            if ignore > 0:
                ignore = ignore - 1
                continue

            bits.append(nextbit)

            if len(bits) == pointwidth:
                codepoint = intfrombits(bits)
                bits = []

                yield codepoint

                codesize = codesize + 1

                if codepoint in [CLEAR_CODE, END_OF_INFO_CODE]:
                    codesize = self._initial_code_size
                    pointwidth = minwidth
                else:
                    while codesize >= (2**pointwidth):
                        pointwidth = pointwidth + 1

                if codepoint == END_OF_INFO_CODE:
                    ignore = (8 - offset) % 8


class Decoder(object):

    def __init__(self):
        self._clear_codes()
        self.remainder = []

    def code_size(self):
        return len(self._codepoints)

    def decode(self, codepoints):
        codepoints = [cp for cp in codepoints]

        for cp in codepoints:
            decoded = self._decode_codepoint(cp)
            for character in decoded:
                bytes([character])

    def _decode_codepoint(self, codepoint):
        ret = b""

        if codepoint == CLEAR_CODE:
            self._clear_codes()
        elif codepoint == END_OF_INFO_CODE:
            raise ValueError(
                "End of information code not supported directly by this Decoder"
            )
        else:
            if codepoint in self._codepoints:
                ret = self._codepoints[codepoint]
                if self._prefix is not None:
                    self._codepoints[len(
                        self._codepoints)] = self._prefix + ret[0:1]

            else:
                ret = self._prefix + self._prefix[0:1]
                self._codepoints[len(self._codepoints)] = ret

            self._prefix = ret

        return ret

    def _clear_codes(self):
        self._codepoints = dict(
            (pt, struct.pack("B", pt)) for pt in range(256))
        self._codepoints[CLEAR_CODE] = CLEAR_CODE
        self._codepoints[END_OF_INFO_CODE] = END_OF_INFO_CODE
        self._prefix = None


def intfrombits(bits):
    ret = 0
    lsb_first = [b for b in bits]
    lsb_first.reverse()

    for bit_index in range(len(lsb_first)):
        if lsb_first[bit_index]:
            ret = ret | (1 << bit_index)

    return ret


def bytestobits(bytesource):
    for value in bytesource:
        for bitplusone in range(8, 0, -1):
            bitindex = bitplusone - 1
            nextbit = 1 & (value >> bitindex)
            yield nextbit

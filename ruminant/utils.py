from .oids import OIDS
from .constants import PGP_HASHES, PGP_PUBLIC_KEYS, PGP_CIPHERS, PGP_AEADS, PGP_SIGNATURE_TYPES
from .buf import Buf, _decode
from .modules import chew
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
import zlib
import bz2
import base64


def _xml_to_dict(elem):
    res = {}

    if elem.tag:
        res["tag"] = elem.tag

    if elem.attrib:
        res["attributes"] = elem.attrib
        res["parsed"] = {}

        for k, v in elem.attrib.items():
            match k:
                case "{http://ns.google.com/photos/1.0/camera/}hdrp_makernote" | "{http://ns.google.com/photos/1.0/camera/}shot_log_data":
                    res["parsed"][k] = chew(base64.b64decode(v))

        if res["parsed"] == {}:
            del res["parsed"]

    if elem.text and len(elem.text.strip()):
        res["text"] = elem.text

    children = list(elem)
    if len(children):
        res["children"] = [_xml_to_dict(child) for child in children]

    return res


def xml_to_dict(string, fail=False):
    while len(string):
        try:
            return _xml_to_dict(ET.fromstring(string))
        except ET.ParseError as e:
            if fail:
                raise e

            string = string[:-1]

    return {}


def read_varint(buf):
    i = 0
    o = 0
    c = 0x80
    while c & 0x80:
        c = buf.read(1)[0]
        i |= (c & 0x7f) << o
        o += 7

    return i


def read_protobuf(buf, length, escape=False):
    buf.pushunit()
    buf.setunit(length)

    entries = []
    while buf.unit > 0:
        entry_id = read_varint(buf)
        entry_type = entry_id & 0b111
        entry_id >>= 3

        match entry_type:
            case 0:
                value = read_varint(buf)
                if escape:
                    entry_type = "VARINT"
            case 1:
                value = buf.ru64l()
                if escape:
                    entry_type = "I64"
            case 2:
                value_length = read_varint(buf)
                value = buf.read(value_length)
                if escape:
                    value = value.hex()
                    entry_type = "LEN"
            case 5:
                value = buf.ru32l()
                if escape:
                    entry_type = "I32"
            case _:
                break

        entries.append([entry_id, entry_type, value])

    buf.skipunit()
    buf.popunit()

    return entries


def to_uuid(blob):
    try:
        return str(uuid.UUID(bytes=blob))
    except ValueError:
        return blob.hex()


def mp4_time_to_iso(mp4_time):
    mp4_epoch = datetime(1904, 1, 1, tzinfo=timezone.utc)
    dt = mp4_epoch + timedelta(seconds=mp4_time)
    return dt.isoformat()


def stream_deflate(src, dst, compressed_size, chunk_size=1 << 24):
    remaining = compressed_size
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

    while remaining > 0:
        chunk = src.read(min(chunk_size, remaining))
        dst.write(decompressor.decompress(chunk))
        remaining -= len(chunk)

    flushed = decompressor.flush()
    if flushed:
        dst.write(flushed)


def stream_bzip2(src, dst, compressed_size, chunk_size=1 << 24):
    remaining = compressed_size
    decompressor = bz2.BZ2Decompressor()

    while remaining > 0:
        chunk = src.read(min(chunk_size, remaining))
        dst.write(decompressor.decompress(chunk))
        remaining -= len(chunk)

    src.seek(-len(decompressor.unused_data), 1)


def read_oid(buf, limit=-1):
    oid = []
    c = buf.ru8()
    oid.append(c // 40)
    oid.append(c % 40)

    i = 0
    while buf.unit > 0 and limit != 0:
        c = buf.ru8()
        i <<= 7
        i |= c & 0x7f

        if not c & 0x80:
            oid.append(i)
            i = 0

        limit -= 1

    return lookup_oid(oid)


def read_der(buf):
    data = {}

    tag = buf.ru8()
    constructed = bool((tag >> 5) & 0x01)

    if tag & 0x0f == 0x0f:
        c = 0x80
        while c & 0x80:
            c = buf.ru8()
            tag <<= 7
            tag |= c & 0x7f

    length = buf.ru8()
    if length & 0x80:
        length = int.from_bytes(buf.read(length & 0x7f), "big")

    buf.pushunit()
    buf.setunit(length)

    data["type"] = None
    data["length"] = length

    match tag:
        case 0x01:
            data["type"] = "BOOLEAN"
            data["value"] = bool(buf.ru8())
        case 0x02 | 0x0a:
            data["type"] = ["INTEGER", "ENUMERATED"][tag >> 3]
            data["value"] = int.from_bytes(buf.readunit(), "big", signed=True)
        case 0x03:
            data["type"] = "BIT STRING"
            skip = buf.ru8()
            bit_length = length * 8 - skip

            if skip % 8 == 0:
                nested = True
                with buf:
                    try:
                        if buf.ru8() & 0x0f == 0x0f:
                            c = 0x80
                            while c & 0x80:
                                c = buf.ru8()

                        length = buf.ru8()
                        if length & 0x80:
                            length = int.from_bytes(buf.read(length & 0x7f),
                                                    "big")

                        assert buf.unit == length
                    except Exception:
                        nested = False

                if nested:
                    with buf.subunit():
                        data["value"] = read_der(buf)
                else:
                    data["value"] = bin(int.from_bytes(
                        buf.readunit()))[2:].zfill(bit_length)
            else:
                data["value"] = bin(int.from_bytes(buf.readunit()) >> skip
                                    )[2:].zfill(bit_length)
        case 0x04:
            data["type"] = "OCTET STRING"

            nested = True
            with buf:
                try:
                    if buf.ru8() & 0x0f == 0x0f:
                        c = 0x80
                        while c & 0x80:
                            c = buf.ru8()

                    length = buf.ru8()
                    if length & 0x80:
                        length = int.from_bytes(buf.read(length & 0x7f), "big")

                    assert buf.unit == length
                except Exception:
                    nested = False

            if nested:
                with buf.subunit():
                    data["value"] = read_der(buf)
            else:
                data["value"] = buf.readunit().hex()
        case 0x05:
            data["type"] = "NULL"
            data["value"] = None
        case 0x06:
            data["type"] = "OBJECT IDENTIFIER"
            data["value"] = read_oid(buf)
        case 0x0c:
            data["type"] = "UTF8String"
            data["value"] = buf.readunit().decode("utf-8")
        case 0x10 | 0x11 | 0x30 | 0x31:
            data["type"] = ["SEQUENCE", "SET"][tag & 0x01]
        case 0x13 | 0x14 | 0x16:
            data["type"] = {
                0x13: "PrintableString",
                0x14: "T61String",
                0x16: "IA5String",
            }[tag]

            data["value"] = buf.readunit().decode("ascii")
        case 0x17:
            data["type"] = "UTCTime"

            dt = datetime.strptime(buf.readunit().decode("ascii")[:-1],
                                   "%y%m%d%H%M%S")

            if dt.year < 1950:
                dt = dt.replace(year=dt.year + 100)

            data["value"] = dt.isoformat()
        case 0x18:
            data["type"] = "GeneralizedTime"

            time_string = buf.readunit().decode("ascii")[:-1]
            if '.' in time_string:
                main_time, fraction = time_string.split(".", 1)
                fraction = (fraction + "000000")[:6]
                data["value"] = datetime.strptime(
                    main_time, "%Y%m%d%H%M%S").replace(
                        microsecond=int(fraction)).isoformat(
                            timespec="microseconds") + "Z"
            else:
                data["value"] = datetime.strptime(time_string,
                                                  "%Y%m%d%H%M%S").isoformat()
        case _:
            data["type"] = f"UNKNOWN ({hex(tag)})"

    if tag >= 0x80 and tag <= 0xbe:
        data["type"] = f"X509 [{tag & 0x0f}]"

        if not constructed:
            content = buf.readunit()

            if tag & 0x0f in (0x02, 0x06):
                data["value"] = content.decode("latin-1")
            else:
                data["value"] = content.hex()

    if constructed:
        data["value"] = []
        while buf.unit > 0:
            data["value"].append(read_der(buf))

    buf.skipunit()
    buf.popunit()

    return data


def lookup_oid(oid):
    data = {}
    data["raw"] = ".".join([str(x) for x in oid])

    tree = []
    root = OIDS
    for i in oid:
        if i in root:
            tree.append(root[i]["name"])
            root = root[i]["children"]
        else:
            tree.append("?")
            root = {}

    data["tree"] = tree
    if tree[-1] != "?":
        data["name"] = tree[-1]

    return data


def zlib_decompress(content):
    try:
        return zlib.decompress(content)
    except Exception:
        try:
            return zlib.decompressobj().decompress(content)
        except Exception:
            decomp = zlib.decompressobj(zlib.MAX_WBITS | 32)

            data = b""
            for c in content:
                # WHAT THE FUCK ADOBE
                try:
                    data += decomp.decompress(bytes([c]))
                except Exception:
                    pass

            return data


def decode(*args, **kwargs):
    return _decode(*args, **kwargs)


def unraw(i, width, choices):
    return {"raw": i, "name": choices.get(i, "Unknown")}


def read_pgp_mpi(buf):
    bit_length = buf.ru16()
    return int.from_bytes(buf.read(
        (bit_length + 7) // 8), "big") & ((1 << bit_length) - 1)


def read_pgp_subpacket(buf):
    packet = {}

    length = buf.ru8()
    if length >= 192 and length < 255:
        length = ((length - 192) << 8) + buf.ru8() + 192
    elif length == 255:
        length = buf.ru32()

    buf.pushunit()
    buf.setunit(length)

    packet["length"] = length

    typ = buf.ru8()
    packet["type"] = None

    data = {}
    packet["data"] = data

    match typ & 0x7f:
        case 0x02:
            packet["type"] = "Signature Creation Time"
            data["time"] = datetime.fromtimestamp(buf.ru32(),
                                                  timezone.utc).isoformat()
        case 0x03:
            packet["type"] = "Signature Expiration Time"
            data["expiration-offset"] = buf.ru32()
        case 0x04:
            packet["type"] = "Expiration Time"
            data["expiration-offset"] = buf.ru32()
        case 0x05:
            packet["type"] = "Trust Signature"
            data["depth"] = buf.ru8()
            data["trust"] = buf.ru8()
        case 0x09:
            packet["type"] = "Key Expiration Time"
            data["expiration-offset"] = buf.ru32()
        case 0x0b:
            packet["type"] = "Preferred Symmetric Algorithms"

            data["algorithms"] = []
            while buf.unit > 0:
                data["algorithms"].append(unraw(buf.ru8(), 1, PGP_CIPHERS))
        case 0x10:
            packet["type"] = "Issuer"
            data["key-id"] = buf.rh(8)
        case 0x14:
            packet["type"] = "Notation Data"
            data["flags"] = {
                "raw": buf.ph(4),
                "human-readable": bool(buf.ru32l() & 0x80)
            }

            name_length = buf.ru16()
            value_length = buf.ru16()

            data["name"] = buf.rs(name_length)

            if data["flags"]["human-readable"]:
                data["value"] = buf.rs(value_length)
            else:
                data["value"] = buf.rh(value_length)
        case 0x15:
            packet["type"] = "Preferred Hash Algorithms"

            data["algorithms"] = []
            while buf.unit > 0:
                data["algorithms"].append(unraw(buf.ru8(), 1, PGP_HASHES))
        case 0x16:
            packet["type"] = "Preferred Compression Algorithms"

            data["algorithms"] = []
            while buf.unit > 0:
                data["algorithms"].append(
                    unraw(buf.ru8(), 1, {
                        0: "Uncompressed",
                        1: "ZIP",
                        2: "ZLIB",
                        3: "BZip2"
                    }))
        case 0x17:
            packet["type"] = "Key Server Preferences"
            flags = buf.read(buf.unit)
            data["flags"] = {
                "raw": flags.hex(),
                "no-modify": bool(flags[0] & 0x80)
            }
        case 0x18:
            packet["type"] = "Preferred Key Server"
            data["uri"] = buf.readunit().decode("utf-8")
        case 0x19:
            packet["type"] = "Primary User ID"
            data["is-primary-user-id"] = bool(buf.ru8())
        case 0x1a:
            packet["type"] = "Policy URI"
            data["uri"] = buf.readunit().decode("utf-8")
        case 0x1b:
            packet["type"] = "Key Flags"
            flags = buf.ru8()
            data["flags"] = {
                "raw": flags,
                "can-certify-user-id": bool(flags & (1 << 0)),
                "can-sign-data": bool(flags & (1 << 1)),
                "can-encrypt-communication": bool(flags & (1 << 2)),
                "can-encrypt-storage": bool(flags & (1 << 3)),
                "key-is-split": bool(flags & (1 << 4)),
                "can-authenticate": bool(flags & (1 << 5)),
                "key-is-shared": bool(flags & (1 << 4)),
            }
        case 0x1c:
            packet["type"] = "Signer's User ID"
            data["fingerprint"] = buf.rs(buf.unit)
        case 0x1d:
            packet["type"] = "Reason for Revocation"
            packet["reason"] = unraw(
                buf.ru8(), 1, {
                    0: "No reason specified",
                    1: "Key is superseded",
                    2: "Key material has been compromised",
                    3: "Key is retired and no longer used",
                    32: "User ID information is no longer valid"
                })
            packet["reason-message"] = buf.readunit().decode("utf-8")
        case 0x1e:
            packet["type"] = "Features"

            flags = buf.read(buf.unit)
            data["flags"] = {
                "raw": flags.hex(),
                "use-mdc": bool(flags[0] & 0x01)
            }
        case 0x20:
            packet["type"] = "Embedded Signature"
            data["embedded-packet"] = _read_pgp(buf, fake=(2, buf.unit))
        case 0x21:
            packet["type"] = "Issuer Fingerprint"

            data["version"] = buf.ru8()
            match data["version"]:
                case 4:
                    data["fingerprint"] = buf.rh(buf.unit)
                case _:
                    packet["unknown"] = True
        case 0x22:
            packet["type"] = "Preferred AEAD Algorithms"

            data["algorithms"] = []
            while buf.unit > 0:
                data["algorithms"].append(unraw(buf.ru8(), 1, PGP_AEADS))
        case _:
            if typ & 0x7f >= 100:
                packet["type"] = f"Private (0x{hex(typ)[2:].zfill(2)})"
                packet["content"] = buf.readunit().hex()
            else:
                packet["type"] = f"Unknown (0x{hex(typ)[2:].zfill(2)})"
                packet["unknown"] = True

    buf.skipunit()
    buf.popunit()

    return packet


def _read_pgp(buf, fake=None):
    packet = {}

    if fake is None:
        tag = buf.ru8()
        if tag & 0b01000000:
            tag = tag & 0b00111111

            length = buf.ru8()
            if length >= 192 and length < 255:
                length = ((length - 192) << 8) + buf.ru8() + 192
            elif length == 255:
                length = buf.ru32()
        else:
            packet["old"] = True
            length_type = tag & 0b00000011
            tag = (tag & 0b00111100) >> 2

            match length_type:
                case 0:
                    length = buf.ru8()
                case 1:
                    length = buf.ru16()
                case 2:
                    length = buf.ru32()
                case 3:
                    length = buf.unit
    else:
        tag, length = fake

    buf.pushunit()
    buf.setunit(length)

    packet["length"] = length

    data = {}
    packet["tag"] = None
    packet["data"] = data
    match tag:
        case 0x01:
            packet["tag"] = "Public Key Encrypted Session Key"
            data["version"] = buf.ru8()

            algorithm = None
            match data["version"]:
                case 3:
                    data["key-id"] = buf.rh(8)

                    algorithm = buf.ru8()
                    data["public-key-algorithm"] = unraw(
                        algorithm, 1, PGP_PUBLIC_KEYS)

                case _:
                    packet["unknown"] = True

            match algorithm:
                case 0x01:
                    data["session-key"] = {"c": read_pgp_mpi(buf)}
                case _:
                    data["session-key"] = {"unknown": True}
        case 0x02:
            packet["tag"] = "Signature"
            data["version"] = buf.ru8()

            algorithm = None
            match data["version"]:
                case 3:
                    buf.skip(1)
                    data["type"] = unraw(buf.ru8(), 1, PGP_SIGNATURE_TYPES)
                    data["created-at"] = datetime.fromtimestamp(
                        buf.ru32(), timezone.utc).isoformat()

                    data["key-id"] = buf.rh(8)

                    algorithm = buf.ru8()
                    data["public-key-algorithm"] = unraw(
                        algorithm, 1, PGP_PUBLIC_KEYS)

                    data["hash-algorithm"] = unraw(buf.ru8(), 1, PGP_HASHES)
                    data["hash-prefix"] = buf.rh(2)
                case 4 | 6:
                    data["type"] = unraw(buf.ru8(), 1, PGP_SIGNATURE_TYPES)

                    algorithm = buf.ru8()
                    data["public-key-algorithm"] = unraw(
                        algorithm, 1, PGP_PUBLIC_KEYS)

                    data["hash-algorithm"] = unraw(buf.ru8(), 1, PGP_HASHES)

                    buf.pushunit()
                    buf.setunit(buf.ru16())

                    data["hashed-subpackets"] = []
                    while buf.unit > 0:
                        data["hashed-subpackets"].append(
                            read_pgp_subpacket(buf))

                    buf.skipunit()
                    buf.popunit()

                    buf.pushunit()
                    buf.setunit(buf.ru16())

                    data["unhashed-subpackets"] = []
                    while buf.unit > 0:
                        data["unhashed-subpackets"].append(
                            read_pgp_subpacket(buf))

                    buf.skipunit()
                    buf.popunit()

                    data["hash-prefix"] = buf.rh(2)

                    if data["version"] == 6:
                        data["salt"] = buf.rh(buf.ru8())
                case _:
                    packet["unknown"] = True
            match algorithm:
                case 0x01 | 0x02 | 0x03:
                    data["signature"] = {"c": read_pgp_mpi(buf)}
                case 0x11 | 0x13 | 0x16:
                    data["signature"] = {
                        "r": read_pgp_mpi(buf),
                        "s": read_pgp_mpi(buf)
                    }
                case _:
                    data["signature"] = {"unknown": True}
        case 0x04:
            packet["tag"] = "One-pass Signature"
            data["version"] = buf.ru8()

            match data["version"]:
                case 3:
                    data["type"] = unraw(buf.ru8(), 1, PGP_SIGNATURE_TYPES)
                    data["hash-algorithm"] = unraw(buf.ru8(), 1, PGP_HASHES)
                    data["public-key-algorithm"] = unraw(
                        buf.ru8(), 1, PGP_PUBLIC_KEYS)
                    data["key-id"] = buf.rh(8)
                    data["nested"] = buf.ru8() == 0
                case _:
                    packet["unknown"] = True
        case 0x05 | 0x06 | 0x07 | 0x0e:
            packet["tag"] = {
                0x05: "Secret Key",
                0x06: "Public Key",
                0x07: "Secret Subkey",
                0x0e: "Public Subkey"
            }[tag]
            data["version"] = buf.ru8()

            secret = {0x05: True, 0x06: False, 0x07: True, 0x0e: False}[tag]

            algorithm = None
            match data["version"]:
                case 3:
                    data["created-at"] = datetime.fromtimestamp(
                        buf.ru32(), timezone.utc).isoformat()
                    data["expiry-days"] = buf.ru16()
                    algorithm = buf.ru8()

                    data["algorithm"] = unraw(algorithm, 1, PGP_PUBLIC_KEYS)
                case 4:
                    data["created-at"] = datetime.fromtimestamp(
                        buf.ru32(), timezone.utc).isoformat()
                    algorithm = buf.ru8()

                    data["algorithm"] = unraw(algorithm, 1, PGP_PUBLIC_KEYS)
                case _:
                    packet["unknown"] = True

            match algorithm:
                case 0x01 | 0x02 | 0x03:
                    data["key"] = {
                        "n": read_pgp_mpi(buf),
                        "e": read_pgp_mpi(buf)
                    }
                case 0x10:
                    data["key"] = {
                        "p": read_pgp_mpi(buf),
                        "g": read_pgp_mpi(buf),
                        "y": read_pgp_mpi(buf)
                    }
                case 0x11:
                    data["key"] = {
                        "p": read_pgp_mpi(buf),
                        "q": read_pgp_mpi(buf),
                        "g": read_pgp_mpi(buf),
                        "y": read_pgp_mpi(buf)
                    }
                case 0x12:
                    data["key"] = {
                        "oid": read_oid(buf,
                                        buf.ru8() - 1),
                        "point": read_pgp_mpi(buf)
                    }

                    length = buf.ru8()
                    buf.skip(1)
                    data["key"]["kdf-hash-function"] = unraw(
                        buf.ru8(), 1, PGP_HASHES)
                    data["key"]["kdf-cipher"] = unraw(buf.ru8(), 1,
                                                      PGP_CIPHERS)

                    if length > 3:
                        data["key"]["sender"] = buf.rs(32)
                        data["key"]["fingerprint"] = buf.rh(length - 35)
                case 0x13 | 0x16:
                    data["key"] = {
                        "oid": read_oid(buf,
                                        buf.ru8() - 1),
                        "point": read_pgp_mpi(buf)
                    }
                case _:
                    packet["unknown"] = True

            if secret:
                s2k_usage = buf.ru8()
                data["s2k-usage"] = unraw(s2k_usage, 1, {
                    0: "Unencrypted",
                    253: "AEAD",
                    254: "CFB",
                    255: "MalleableCFB"
                })
        case 0x08:
            packet["tag"] = "Compressed Data"

            method = buf.ru8()
            data["method"] = unraw(method, 1, {
                0: "Uncompressed",
                1: "ZIP",
                2: "ZLIB",
                3: "BZip2"
            })

            content = buf.readunit()
            match method:
                case 0:
                    pass
                case 1:
                    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                    content = decompressor.decompress(
                        content) + decompressor.flush()
                case 2:
                    content = zlib.decompress(content)
                case 3:
                    content = bz2.decompress(content)
                case _:
                    content = None

            if content is not None:
                cbuf = Buf(content)

                data["content"] = []
                while cbuf.available() > 0:
                    data["content"].append(read_pgp(cbuf))
            else:
                data["unknown"] = True
        case 0x0b:
            packet["tag"] = "Literal Data"
            data["format"] = buf.rs(1)
            data["filename"] = buf.rs(buf.ru8())
            data["date"] = datetime.fromtimestamp(buf.ru32(),
                                                  timezone.utc).isoformat()

            match data["format"]:
                case "t" | "b":
                    data["content"] = buf.rs(buf.unit)
                case _:
                    packet["unknown"] = True
        case 0x0d:
            packet["tag"] = "User ID"
            data["user-id"] = buf.rs(buf.unit)
        case 0x12:
            packet[
                "tag"] = "Symetrically Encrypted and Integrity Protected Data"
            data["version"] = buf.ru8()

            match data["version"]:
                case 0x01:
                    data["encrypted-length"] = buf.unit
                    buf.skipunit()
                case _:
                    packet["unknown"] = True
        case _:
            packet["tag"] = f"Unknown (0x{hex(tag)[2:].zfill(2)})"
            packet["unknown"] = True

    buf.skipunit()
    buf.popunit()

    return packet


def read_pgp(buf):
    buf.pushunit()
    buf.setunit(buf.available() if buf.unit is None else buf.unit)

    data = _read_pgp(buf)

    buf.popunit()

    return data

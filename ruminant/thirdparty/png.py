# based on https://github.com/py-pdf/pypdf/blob/47a7f8fae02aa06585f8c8338dcab647e2547917/pypdf/filters.py#L204
# licensed under BSD-3
# see https://github.com/py-pdf/pypdf/blob/47a7f8fae02aa06585f8c8338dcab647e2547917/LICENSE for attribution


def png_decode(data, columns, rowlength):
    output = b""
    prev_rowdata = bytes(rowlength)
    bpp = (rowlength - 1) // columns
    for row in range(0, len(data), rowlength):
        rowdata = bytearray(data[row : row + rowlength])
        cmd = rowdata[0]

        match cmd:
            case 0:
                pass
            case 1:
                for i in range(bpp + 1, rowlength):
                    rowdata[i] = (rowdata[i] + rowdata[i - bpp]) % 256
            case 2:
                for i in range(1, rowlength):
                    rowdata[i] = (rowdata[i] + prev_rowdata[i]) % 256
            case 3:
                for i in range(1, bpp + 1):
                    floor = prev_rowdata[i] // 2
                    rowdata[i] = (rowdata[i] + floor) % 256
                for i in range(bpp + 1, rowlength):
                    left = rowdata[i - bpp]
                    floor = (left + prev_rowdata[i]) // 2
                    rowdata[i] = (rowdata[i] + floor) % 256
            case 4:
                for i in range(1, bpp + 1):
                    up = prev_rowdata[i]
                    paeth = up
                    rowdata[i] = (rowdata[i] + paeth) % 256
                for i in range(bpp + 1, rowlength):
                    left = rowdata[i - bpp]
                    up = prev_rowdata[i]
                    up_left = prev_rowdata[i - bpp]
                    p = left + up - up_left
                    dist_left = abs(p - left)
                    dist_up = abs(p - up)
                    dist_up_left = abs(p - up_left)
                    if dist_left <= dist_up and dist_left <= dist_up_left:
                        paeth = left
                    elif dist_up <= dist_up_left:
                        paeth = up
                    else:
                        paeth = up_left
                    rowdata[i] = (rowdata[i] + paeth) % 256
            case _:
                raise ValueError(f"Unsupported PNG predictor {cmd}")

        prev_rowdata = bytes(rowdata)
        output += rowdata[1:]

    return output

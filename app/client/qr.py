"""Pure-Python ISO/IEC 18004 QR Code encoder (Byte mode, Level L, Versions 1..14) with UTF-8 terminal rendering."""

from typing import Sequence

# (total_codewords, ec_codewords_per_block, num_blocks_group1, data_cw_group1, num_blocks_group2, data_cw_group2)
_VERSION_L_TABLE: dict[int, tuple[int, int, int, int, int, int]] = {
    1: (26, 7, 1, 19, 0, 0),
    2: (44, 10, 1, 34, 0, 0),
    3: (70, 15, 1, 55, 0, 0),
    4: (100, 20, 1, 80, 0, 0),
    5: (134, 26, 1, 108, 0, 0),
    6: (172, 18, 2, 68, 0, 0),
    7: (196, 20, 2, 78, 0, 0),
    8: (242, 24, 2, 97, 0, 0),
    9: (292, 30, 2, 116, 0, 0),
    10: (346, 18, 2, 68, 2, 69),
    11: (404, 20, 4, 81, 0, 0),
    12: (466, 24, 2, 92, 2, 93),
    13: (532, 26, 4, 107, 0, 0),
    14: (581, 30, 3, 115, 1, 116),
}

_ALIGNMENT_POSITIONS: dict[int, list[int]] = {
    1: [],
    2: [6, 18],
    3: [6, 22],
    4: [6, 26],
    5: [6, 30],
    6: [6, 34],
    7: [6, 22, 38],
    8: [6, 24, 42],
    9: [6, 26, 46],
    10: [6, 28, 50],
    11: [6, 30, 54],
    12: [6, 32, 58],
    13: [6, 34, 62],
    14: [6, 26, 46, 66],
}


def _gf_tables() -> tuple[list[int], list[int]]:
    exp = [0] * 512
    log = [0] * 256
    val = 1
    for i in range(255):
        exp[i] = val
        log[val] = i
        val <<= 1
        if val & 0x100:
            val ^= 0x11D
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


_GF_EXP, _GF_LOG = _gf_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _rs_generator_poly(degree: int) -> list[int]:
    poly = [1]
    for i in range(degree):
        next_poly = [0] * (len(poly) + 1)
        factor = _GF_EXP[i]
        for j, coeff in enumerate(poly):
            next_poly[j] ^= coeff
            next_poly[j + 1] ^= _gf_mul(coeff, factor)
        poly = next_poly
    return poly


def _rs_encode(data: Sequence[int], ec_len: int) -> list[int]:
    gen = _rs_generator_poly(ec_len)
    reg = [0] * ec_len
    for byte in data:
        factor = byte ^ reg[0]
        reg = reg[1:] + [0]
        if factor != 0:
            for i in range(ec_len):
                reg[i] ^= _gf_mul(gen[i + 1], factor)
    return reg


def _select_version(payload_len: int) -> int:
    for ver, (
        _,
        _,
        b1,
        d1,
        b2,
        d2,
    ) in _VERSION_L_TABLE.items():
        data_capacity = b1 * d1 + b2 * d2
        header_bytes = 2 if ver <= 9 else 3
        if payload_len + header_bytes <= data_capacity:
            return ver
    raise ValueError(f"QR payload too long ({payload_len} bytes)")


def _encode_data_codewords(payload: bytes, version: int) -> list[int]:
    _, ec_len, b1, d1, b2, d2 = _VERSION_L_TABLE[version]
    total_data = b1 * d1 + b2 * d2
    bits: list[int] = []

    def append_bits(val: int, count: int) -> None:
        for i in range(count - 1, -1, -1):
            bits.append((val >> i) & 1)

    # Byte mode indicator = 0100
    append_bits(0b0100, 4)
    count_bits = 8 if version <= 9 else 16
    append_bits(len(payload), count_bits)
    for b in payload:
        append_bits(b, 8)

    max_bits = total_data * 8
    terminator = min(4, max_bits - len(bits))
    append_bits(0, terminator)
    while len(bits) % 8 != 0:
        bits.append(0)

    codewords: list[int] = []
    for i in range(0, len(bits), 8):
        byte_val = 0
        for bit in bits[i : i + 8]:
            byte_val = (byte_val << 1) | bit
        codewords.append(byte_val)

    pad_bytes = [0xEC, 0x11]
    pad_idx = 0
    while len(codewords) < total_data:
        codewords.append(pad_bytes[pad_idx % 2])
        pad_idx += 1

    blocks_data: list[list[int]] = []
    blocks_ec: list[list[int]] = []
    offset = 0
    for _ in range(b1):
        chunk = codewords[offset : offset + d1]
        offset += d1
        blocks_data.append(chunk)
        blocks_ec.append(_rs_encode(chunk, ec_len))
    for _ in range(b2):
        chunk = codewords[offset : offset + d2]
        offset += d2
        blocks_data.append(chunk)
        blocks_ec.append(_rs_encode(chunk, ec_len))

    interleaved: list[int] = []
    max_data_len = max(d1, d2)
    for col in range(max_data_len):
        for blk in blocks_data:
            if col < len(blk):
                interleaved.append(blk[col])
    for col in range(ec_len):
        for blk in blocks_ec:
            interleaved.append(blk[col])
    return interleaved


def _place_finder(
    matrix: list[list[int | None]], reserved: list[list[bool]], r: int, c: int
) -> None:
    size = len(matrix)
    for dr in range(-1, 8):
        for dc in range(-1, 8):
            rr, cc = r + dr, c + dc
            if 0 <= rr < size and 0 <= cc < size:
                if (
                    0 <= dr <= 6
                    and 0 <= dc <= 6
                    and (
                        dr in (0, 6)
                        or dc in (0, 6)
                        or (2 <= dr <= 4 and 2 <= dc <= 4)
                    )
                ):
                    matrix[rr][cc] = 1
                else:
                    matrix[rr][cc] = 0
                reserved[rr][cc] = True


def _place_alignment(
    matrix: list[list[int | None]], reserved: list[list[bool]], r: int, c: int
) -> None:
    for dr in range(-2, 3):
        for dc in range(-2, 3):
            rr, cc = r + dr, c + dc
            if (
                max(abs(dr), abs(dc)) in (2, 0)
            ):
                matrix[rr][cc] = 1
            else:
                matrix[rr][cc] = 0
            reserved[rr][cc] = True


def _format_bits_l(mask: int) -> int:
    # EC Level L = 01
    data = (0b01 << 3) | mask
    rem = data << 10
    for i in range(14, 9, -1):
        if (rem >> i) & 1:
            rem ^= 0x537 << (i - 10)
    return ((data << 10) | rem) ^ 0x5412


def _version_bits(version: int) -> int:
    rem = version << 12
    for i in range(17, 11, -1):
        if (rem >> i) & 1:
            rem ^= 0x1F25 << (i - 12)
    return (version << 12) | rem


def encode_qr_matrix(text: str) -> list[list[int]]:
    payload = text.encode("utf-8")
    version = _select_version(len(payload))
    size = 17 + 4 * version
    matrix: list[list[int | None]] = [[None] * size for _ in range(size)]
    reserved: list[list[bool]] = [[False] * size for _ in range(size)]

    _place_finder(matrix, reserved, 0, 0)
    _place_finder(matrix, reserved, 0, size - 7)
    _place_finder(matrix, reserved, size - 7, 0)

    centers = _ALIGNMENT_POSITIONS[version]
    for r in centers:
        for c in centers:
            if not reserved[r][c]:
                _place_alignment(matrix, reserved, r, c)

    for i in range(8, size - 8):
        val = 1 if i % 2 == 0 else 0
        if not reserved[6][i]:
            matrix[6][i] = val
            reserved[6][i] = True
        if not reserved[i][6]:
            matrix[i][6] = val
            reserved[i][6] = True

    # Dark module & format reservation
    matrix[size - 8][8] = 1
    reserved[size - 8][8] = True
    for i in range(9):
        if i < size:
            reserved[8][i] = True
            reserved[i][8] = True
    for i in range(8):
        reserved[8][size - 1 - i] = True
        reserved[size - 1 - i][8] = True

    if version >= 7:
        vbits = _version_bits(version)
        for i in range(18):
            bit = (vbits >> i) & 1
            r, c = i // 3, size - 11 + (i % 3)
            matrix[r][c] = bit
            reserved[r][c] = True
            matrix[c][r] = bit
            reserved[c][r] = True

    codewords = _encode_data_codewords(payload, version)
    bit_stream: list[int] = []
    for cw in codewords:
        for b in range(7, -1, -1):
            bit_stream.append((cw >> b) & 1)

    bit_idx = 0
    col = size - 1
    upward = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(size - 1, -1, -1) if upward else range(size)
        for row in rows:
            for dc in (0, -1):
                c = col + dc
                if not reserved[row][c]:
                    bit = (
                        bit_stream[bit_idx]
                        if bit_idx < len(bit_stream)
                        else 0
                    )
                    bit_idx += 1
                    # Mask 0: (row + c) % 2 == 0
                    if (row + c) % 2 == 0:
                        bit ^= 1
                    matrix[row][c] = bit
        upward = not upward
        col -= 2

    fbits = _format_bits_l(0)
    fmt_coords_1 = [
        (8, 0),
        (8, 1),
        (8, 2),
        (8, 3),
        (8, 4),
        (8, 5),
        (8, 7),
        (8, 8),
        (7, 8),
        (5, 8),
        (4, 8),
        (3, 8),
        (2, 8),
        (1, 8),
        (0, 8),
    ]
    for i, (r, c) in enumerate(fmt_coords_1):
        matrix[r][c] = (fbits >> (14 - i)) & 1

    for i in range(7):
        matrix[size - 1 - i][8] = (fbits >> (14 - i)) & 1
    for i in range(7, 15):
        matrix[8][size - 15 + i] = (fbits >> (14 - i)) & 1

    return [[int(cell or 0) for cell in row] for row in matrix]


def render_qr_utf8(text: str, border: int = 4) -> str:
    """Render a scannable QR code using UTF-8 half-block characters with bright-white quiet zone."""
    raw = encode_qr_matrix(text)
    size = len(raw)
    padded_size = size + 2 * border
    grid = [[0] * padded_size for _ in range(padded_size)]
    for r in range(size):
        for c in range(size):
            grid[r + border][c + border] = raw[r][c]

    lines: list[str] = []
    for r in range(0, padded_size, 2):
        row_chars: list[str] = ["\033[107;30m"]
        for c in range(padded_size):
            top = grid[r][c]
            bottom = grid[r + 1][c] if r + 1 < padded_size else 0
            if top and bottom:
                row_chars.append("█")
            elif top and not bottom:
                row_chars.append("▀")
            elif not top and bottom:
                row_chars.append("▄")
            else:
                row_chars.append(" ")
        row_chars.append("\033[0m")
        lines.append("".join(row_chars))
    return "\n".join(lines)

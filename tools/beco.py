import struct
import sys
import typing

def _get_unpack_endian_char(be: bool):
    return '>' if be else '<'

class Segment(typing.NamedTuple):
    data: int
    length: int

class Beco:
    MAGIC = b'\x00\x11\x22\x33'
    HEADER_SIZE = 0x10

    def __init__(self, data: bytearray) -> None:
        magic = data[0:4]
        self._be = False
        if magic == Beco.MAGIC:
            self._be = True
        elif magic == bytes(reversed(Beco.MAGIC)):
            self._be = False
        else:
            raise ValueError('Unknown magic')

        self._d = data
        self._num_rows = self._u32(4)
        self._divisor = self._u32(8)

    def get_raw_data(self) -> bytearray:
        return self._d

    def get_num_rows(self) -> int:
        return self._num_rows
    def get_divisor(self) -> int:
        return self._divisor

    def get_row_for_z(self, z: float) -> int:
        row = int(z + 4000.0 + 0.5) // self._divisor
        if row < 0:
            row = 0
        if row > self._num_rows - 2:
            row = self._num_rows - 2
        return row

    def _get_row_offset(self, row: int) -> int:
        return Beco.HEADER_SIZE + 4*self._num_rows + 2*self._u32(Beco.HEADER_SIZE + row * 4)

    def get_segments_for_row(self, row: int) -> typing.List[Segment]:
        l = []
        row_offset = self._get_row_offset(row)
        end_row_offset = self._get_row_offset(row + 1)
        offset = row_offset
        while offset < end_row_offset:
            l.append(Segment(data=self._u16(offset), length=self._u16(offset + 2)))
            offset += 4
        return l

    def get_data(self, x: float, z: float) -> int:
        x_ = int(x + 5000.0 + 0.5)
        # Nintendo does this...
        if self._divisor == 10:
            x_ //= 10
        row = self.get_row_for_z(z)
        row_offset = self._get_row_offset(row)
        end_row_offset = self._get_row_offset(row + 1)

        offset = row_offset
        length = 0
        while offset < end_row_offset:
            segment_data = self._u16(offset)
            segment_length = self._u16(offset + 2)
            length += segment_length
            if x_ < length:
                return segment_data
            offset += 4

        return -1

    def replace_data(self, old_data: int, new_data: int) -> None:
        for i in range(self._num_rows - 2):
            row_offset = self._get_row_offset(i)
            end_row_offset = self._get_row_offset(i + 1)

            offset = row_offset
            while offset < end_row_offset:
                segment_data = self._u16(offset)
                if segment_data == old_data:
                    self._write_u16(offset, new_data)
                offset += 4

    def _write_u16(self, offset: int, v: int) -> None:
        struct.pack_into(_get_unpack_endian_char(self._be) + 'H', self._d, offset, v)
    def _u16(self, offset: int) -> int:
        return struct.unpack_from(_get_unpack_endian_char(self._be) + 'H', self._d, offset)[0]
    def _u32(self, offset: int) -> int:
        return struct.unpack_from(_get_unpack_endian_char(self._be) + 'I', self._d, offset)[0]

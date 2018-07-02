#!/usr/bin/env python3
# Copyright 2018 leoetlino <leo@leolam.fr>
# Licensed under MIT

import binascii
import json
import os
import struct
import typing

def _get_unpack_endian_character(big_endian: bool):
    return '>' if big_endian else '<'

def _read_u32(buf: bytes, offset: int, be: bool) -> int:
    return struct.unpack_from(_get_unpack_endian_character(be) + 'I', buf, offset)[0]

def _to_u32(value, be: bool) -> bytes:
    return struct.pack(_get_unpack_endian_character(be) + 'I', value)

_NUL_CHAR = b"\x00"
def _read_string(buf: bytes, offset: int, be: bool, max_length: int = 0) -> str:
    end = buf.find(_NUL_CHAR, offset)
    if max_length:
        end = min(end, offset + max_length)
    return buf[offset:end].decode('utf-8')

class ResourceSizeTable:
    def __init__(self, buf: bytes, be: bool) -> None:
        self.crc32_map: typing.Dict[int, int] = dict()
        self.name_map: typing.Dict[str, int] = dict()

        crc32_map_bytes: typing.Optional[bytes] = None
        name_map_bytes: typing.Optional[bytes] = None
        if buf[0:4] != b"RSTB":
            crc32_map_bytes = buf
        else:
            crc32_map_size = _read_u32(buf, 4, be)
            crc32_map_end = 12 + crc32_map_size*8
            if crc32_map_size >= 1:
                crc32_map_bytes = buf[12:crc32_map_end]

            name_map_size = _read_u32(buf, 8, be)
            if name_map_size >= 1:
                name_map_bytes = buf[crc32_map_end:crc32_map_end+name_map_size*132]

        if crc32_map_bytes:
            for i in range(int(len(crc32_map_bytes) / 8)):
                crc32 = _read_u32(crc32_map_bytes, 8*i + 0, be)
                size = _read_u32(crc32_map_bytes, 8*i + 4, be)
                self.crc32_map[crc32] = size

        if name_map_bytes:
            for i in range(int(len(name_map_bytes) / 132)):
                name = _read_string(name_map_bytes, 132*i + 0, be, 128)
                size = _read_u32(name_map_bytes, 132*i + 128, be)
                self.name_map[name] = size

    def get_size(self, name: str) -> int:
        """Get a resource size from the RSTB."""
        crc32 = binascii.crc32(name.encode())
        if crc32 in self.crc32_map:
            return self.crc32_map[crc32]

        if name in self.name_map:
            return self.name_map[name]

        return 0

    def set_size(self, name: str, size: int):
        """Set the size of a resource in the RSTB."""
        if self._needs_to_be_in_name_map(name):
            if len(name) >= 128:
                raise ValueError("Name is too long")
            self.name_map[name] = size
        else:
            crc32 = binascii.crc32(name.encode())
            self.crc32_map[crc32] = size

    def delete_entry(self, name: str) -> None:
        crc32 = binascii.crc32(name.encode())
        if crc32 in self.crc32_map:
            del self.crc32_map[crc32]
        if name in self.name_map:
            del self.name_map[name]

    def write(self, stream: typing.BinaryIO, be: bool) -> None:
        """Write the RSTB to the specified stream."""
        stream.write(b'RSTB')
        stream.write(_to_u32(len(self.crc32_map), be))
        stream.write(_to_u32(len(self.name_map), be))

        # The CRC32 hashmap *must* be sorted because the game performs a binary search.
        for crc32, size in sorted(self.crc32_map.items()):
            stream.write(_to_u32(crc32, be))
            stream.write(_to_u32(size, be))

        # The name map does not have to be sorted, but Nintendo seems to do it, so let's sort too.
        for name, size in sorted(self.name_map.items()):
            stream.write(struct.pack('128s', name.encode()))
            stream.write(_to_u32(size, be))

    def is_in_table(self, name: str) -> bool:
        crc32 = binascii.crc32(name.encode())
        if crc32 in self.crc32_map:
            return True
        if name in self.name_map:
            return True
        return False

    def _needs_to_be_in_name_map(self, name: str) -> bool:
        crc32 = binascii.crc32(name.encode())

        for existing_name in self.name_map.keys():
            if binascii.crc32(existing_name.encode()) == crc32:
                return True
        return False

class SizeCalculator:
    def __init__(self) -> None:
        with open(os.path.join(os.path.dirname(__file__), 'resource_class_sizes.json')) as f:
            self._factory_info: typing.Dict[str, dict] = json.load(f)

    def calculate_file_size(self, file_name: str, wiiu: bool) -> int:
        name_without_ext, ext = os.path.splitext(file_name)
        size = 0
        if ext.startswith('.s'):
            with open(file_name, 'rb') as f:
                f.seek(4)
                size = _read_u32(f.read(4), offset=0, be=True)
        else:
            size = os.path.getsize(file_name)

        # Round up the file size to the nearest multiple of 32.
        size = (size + 31) & -32

        actual_ext = ext.replace('.s', '.')[1:]
        if wiiu:
            size += 0xe4 # res::ResourceMgr constant. Not sure what it is.
            size += self._factory_info.get(actual_ext, self._factory_info['*'])['size_wiiu']
        else:
            size += 0x168
            size += self._factory_info.get(actual_ext, self._factory_info['*'])['size_nx']

        return size

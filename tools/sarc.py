#!/usr/bin/env python3
# Originally made by NWPlayer123
# Heavily edited to be usable as a library, handle little endian and fix broken yaz0 support
import io
import os
import struct
import sys
import typing

import yaz0_util

def _get_unpack_endian_character(big_endian: bool):
    return '>' if big_endian else '<'

_NUL_CHAR = b'\x00'

class SARC:
    def __init__(self, data: typing.Union[memoryview, bytes]) -> None:
        self._data = memoryview(data)
        if data[0:4] != b"SARC":
            raise ValueError("Not a SARC")
        self._be = data[6:8] == b"\xFE\xFF"
        if not self._be and data[6:8] != b"\xFF\xFE":
            raise ValueError("Invalid BOM")

        pos = 12
        self._doff: int = self._read_u32(pos);pos += 8 #Start of data section

        magic2 = self._data[pos:pos + 4];pos += 6
        assert magic2 == b"SFAT"
        nodec = self._read_u16(pos);pos += 6 #Node Count
        nodes: list = []
        for x in range(nodec):
            pos += 8
            srt  = self._read_u32(pos);pos += 4 #File Offset Start
            end  = self._read_u32(pos);pos += 4 #File Offset End
            nodes.append([srt, end])

        magic3 = self._data[pos:pos + 4];pos += 8
        assert magic3 == b"SFNT"
        self._files: dict = dict()
        for node in nodes:
            string = self._read_string(pos);pos += len(string)
            while self._data[pos] == 0:
                pos += 1
                if pos >= len(self._data):
                    break
            if pos >= len(self._data):
                break
            self._files[string] = node

    def list_files(self):
        return self._files.keys()

    def is_archive(self, name: str) -> bool:
        node = self._files[name]
        size = node[1] - node[0]
        if size < 4:
            return False

        magic = self._data[self._doff + node[0]:self._doff + node[0] + 4]
        if magic == b"SARC":
            return True
        if magic == b"Yaz0":
            if size < 0x15:
                return False
            fourcc = self._data[self._doff + node[0] + 0x11:self._doff + node[0] + 0x15]
            return fourcc == b"SARC"
        return False

    def get_file_data(self, name: str) -> memoryview:
        node = self._files[name]
        return memoryview(self._data[self._doff + node[0]:self._doff + node[1]])

    def get_file_size(self, name: str) -> int:
        node = self._files[name]
        return node[1] - node[0]

    def extract(self, archive_name: str) -> None:
        name, ext = os.path.splitext(archive_name)
        try: os.mkdir(name)
        except: pass
        for file_name, node in self._files.items():
            filename = name + "/" + file_name
            if not os.path.exists(os.path.dirname(filename)):
                os.makedirs(os.path.dirname(filename))
            filedata = self._data[self._doff + node[0]:self._doff + node[1]]
            print(filename)
            with open(filename, 'wb') as f:
                f.write(filedata) # type: ignore

    def _read_u16(self, offset: int) -> int:
        return struct.unpack_from(_get_unpack_endian_character(self._be) + 'H', self._data, offset)[0]
    def _read_u32(self, offset: int) -> int:
        return struct.unpack_from(_get_unpack_endian_character(self._be) + 'I', self._data, offset)[0]
    def _read_string(self, offset: int) -> str:
        end = self._data.obj.find(_NUL_CHAR, offset) # type: ignore
        return self._data[offset:end].tobytes().decode('utf-8')

class _PlaceholderOffsetWriter:
    """Writes a placeholder offset value that will be filled later."""
    def __init__(self, stream: typing.BinaryIO, parent) -> None:
        self._stream = stream
        self._offset = stream.tell()
        self._parent = parent
    def write_placeholder(self) -> None:
        self._stream.write(self._parent._u32(0xffffffff))
    def write_offset(self, offset: int, base: int = 0) -> None:
        current_offset = self._stream.tell()
        self._stream.seek(self._offset)
        self._stream.write(self._parent._u32(offset - base))
        self._stream.seek(current_offset)
    def write_current_offset(self, base: int = 0) -> None:
        self.write_offset(self._stream.tell(), base)

def _align_up(n: int) -> int:
    return (n + 3) & -4

class SARCWriter:
    class File(typing.NamedTuple):
        name: str
        data: typing.Union[memoryview, bytes]

    def __init__(self, be: bool) -> None:
        self._be = be
        self._hash_multiplier = 0x65
        self._files: typing.Dict[int, SARCWriter.File] = dict()

    def _hash_file_name(self, name: str) -> int:
        h = 0
        for c in name:
            h = (ord(c) + h * self._hash_multiplier) & 0xffffffff
        return h

    def add_file(self, name: str, data: typing.Union[memoryview, bytes]) -> None:
        self._files[self._hash_file_name(name)] = SARCWriter.File(name, data)

    def delete_file(self, name: str) -> None:
        del self._files[self._hash_file_name(name)]

    def write(self, stream: typing.BinaryIO) -> None:
        # SARC header
        stream.write(b'SARC')
        stream.write(self._u16(0x14))
        stream.write(self._u16(0xfeff))
        file_size_writer = self._write_placeholder_offset(stream)
        data_offset_writer = self._write_placeholder_offset(stream)
        stream.write(self._u16(0x100))
        stream.write(self._u16(0)) # Unused.

        # SFAT header
        stream.write(b'SFAT')
        stream.write(self._u16(0xc))
        stream.write(self._u16(len(self._files)))
        stream.write(self._u32(self._hash_multiplier))

        # Node information
        sorted_hashes = sorted(self._files.keys())
        string_offset = 0
        data_offset = 0
        for h in sorted_hashes:
            stream.write(self._u32(h))
            stream.write(self._u32(0x01000000 | (string_offset >> 2)))
            stream.write(self._u32(data_offset))
            data_offset += len(self._files[h].data)
            stream.write(self._u32(data_offset))
            string_offset += _align_up(len(self._files[h].name) + 1)
            data_offset = _align_up(data_offset)

        # File name table
        stream.write(b'SFNT')
        stream.write(self._u16(8))
        stream.write(self._u16(0))
        for h in sorted_hashes:
            stream.write(self._files[h].name.encode())
            stream.write(_NUL_CHAR)
            stream.seek(_align_up(stream.tell()))

        # File data
        data_offset_writer.write_current_offset()
        for i, h in enumerate(sorted_hashes):
            stream.write(self._files[h].data) # type: ignore
            if i != len(sorted_hashes) - 1:
                stream.seek(_align_up(stream.tell()))

        # Write the final file size.
        file_size_writer.write_current_offset()

    def _write_placeholder_offset(self, stream) -> _PlaceholderOffsetWriter:
        p = _PlaceholderOffsetWriter(stream, self)
        p.write_placeholder()
        return p

    def _u16(self, value: int) -> bytes:
        return struct.pack(_get_unpack_endian_character(self._be) + 'H', value)
    def _u32(self, value: int) -> bytes:
        return struct.pack(_get_unpack_endian_character(self._be) + 'I', value)

def read_file_and_make_sarc(f: typing.BinaryIO) -> typing.Optional[SARC]:
    f.seek(0)
    magic: bytes = f.read(4)
    if magic == b"Yaz0":
        f.seek(0x11)
        first_data_group_fourcc: bytes = f.read(4)
        f.seek(0)
        if first_data_group_fourcc != b"SARC":
            return None
        data = yaz0_util.decompress(f.read())
    elif magic == b"SARC":
        f.seek(0)
        data = f.read()
    else:
        return None
    return SARC(data)

def read_sarc_and_make_writer(f: typing.BinaryIO, filter_fn: typing.Optional[typing.Callable[[str], bool]]) -> typing.Optional[SARCWriter]:
    sarc = read_file_and_make_sarc(f)
    if not sarc:
        return None

    writer = SARCWriter(be=sarc._be)
    for file in sarc.list_files():
        if not filter_fn or filter_fn(file):
            writer.add_file(file, sarc.get_file_data(file))

    return writer

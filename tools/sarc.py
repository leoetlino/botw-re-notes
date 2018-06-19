#!/usr/bin/env python3
# Originally made by NWPlayer123
# Heavily edited to be usable as a library, handle little endian and fix broken yaz0 support
import os
import struct
import sys
import typing

import yaz0

def _get_unpack_endian_character(big_endian: bool):
    return '>' if big_endian else '<'

_NUL_CHAR = b'\x00'

class SARC:
    def __init__(self, data: bytes) -> None:
        self._data = data
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
            f = open(filename, "wb")
            f.write(filedata)
            f.close()

    def _read_u16(self, offset: int) -> int:
        return struct.unpack_from(_get_unpack_endian_character(self._be) + 'H', self._data, offset)[0]
    def _read_u32(self, offset: int) -> int:
        return struct.unpack_from(_get_unpack_endian_character(self._be) + 'I', self._data, offset)[0]
    def _read_string(self, offset: int) -> str:
        end = self._data.find(_NUL_CHAR, offset)
        return self._data[offset:end].decode('utf-8')

def read_file_and_make_sarc(file_name: str) -> typing.Optional[SARC]:
    with open(file_name, "rb") as f:
        magic: bytes = f.read(4)
        if magic == b"Yaz0":
            f.seek(0x11)
            first_data_group_fourcc: bytes = f.read(4)
            f.seek(0)
            if first_data_group_fourcc != b"SARC":
                return None
            data = yaz0.decompress(f)
        elif magic == b"SARC":
            f.seek(0)
            data = f.read()
        else:
            return None
        return SARC(data)

def extract() -> None:
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: SARCExtract archive.szs\n")
        sys.exit(1)

    s = read_file_and_make_sarc(sys.argv[1])
    if not s:
        sys.stderr.write("Unknown File Format!\n")
        sys.exit(1)
    s.extract(sys.argv[1])

if __name__ == "__main__":
    extract()

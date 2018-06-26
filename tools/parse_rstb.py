#!/usr/bin/env python3
import argparse
import binascii
import csv
import os
import struct
import sys
import typing

import sarc
import yaz0

def _get_unpack_endian_character(big_endian: bool):
    return '>' if big_endian else '<'

_NUL_CHAR = b"\x00"
def _read_u32(buf: bytes, offset: int, be: bool) -> int:
    return struct.unpack_from(_get_unpack_endian_character(be) + 'I', buf, offset)[0]
def _read_string(buf: bytes, offset: int, be: bool, max_length: int = 0) -> str:
    end = buf.find(_NUL_CHAR, offset)
    if max_length:
        end = min(end, offset + max_length)
    return buf[offset:end].decode('utf-8')

def parse_args():
    parser = argparse.ArgumentParser(description='Parses a RSTB (Resource Size TaBle) file.')
    parser.add_argument('content_dir', help='Path to a Breath of the Wild content root')
    parser.add_argument('-b', '--be', action='store_true', help='Use big endian. Defaults to false.')
    parser.add_argument('--csv', type=argparse.FileType('w'), nargs='?',
                        help='Path to output CSV for size information')
    args = parser.parse_args()

    if not os.path.isdir(args.content_dir):
        sys.stderr.write("%s is not actually a dir\n" % args.content_dir)
        sys.exit(1)

    return args

def read_rstb(content_dir: str, be: bool):
    crc32_map_bytes: typing.Optional[bytes] = None
    name_map_bytes: typing.Optional[bytes] = None
    with open("%s/System/Resource/ResourceSizeTable.product.srsizetable" % content_dir, "rb") as file:
        buf = yaz0.decompress(file)
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

    return (crc32_map_bytes, name_map_bytes)

def get_name_and_extension(path: str):
    res_name_without_ext, ext = os.path.splitext(path)
    return (res_name_without_ext, ext[1:]) # get rid of the leading dot in extension

Crc32ToNameMap = typing.Dict[int, typing.Tuple[str, str]]
def make_crc32_to_name_map(content_dir: str) -> Crc32ToNameMap:
    crc32_to_name_map: Crc32ToNameMap = dict()

    def add_entry(name: str, full_name: str) -> None:
        crc32 = binascii.crc32(name.encode())
        print("%08x -> (%s, %s)" % (crc32, name, full_name))
        crc32_to_name_map[crc32] = (name, full_name)

    def handle_file(res_name: str, full_name: str, stream: typing.Optional[typing.BinaryIO]) -> None:
        add_entry(res_name, full_name=full_name)

        res_name_without_ext, ext = get_name_and_extension(res_name)
        full_name_without_ext, ext = get_name_and_extension(full_name)
        if ext.startswith('s'):
            res_name = "%s.%s" % (res_name_without_ext, ext[1:])
            full_name = "%s.%s" % (full_name_without_ext, ext[1:])
            add_entry(res_name, full_name=full_name)

        if not stream:
            return
        arc = sarc.read_file_and_make_sarc(stream)
        if arc:
            for arc_res_name in arc.list_files():
                full_arc_res_name = "%s/%s" % (full_name, arc_res_name)
                _stream = arc.get_file_data(arc_res_name) if arc.is_archive(arc_res_name) else None
                handle_file(arc_res_name, full_arc_res_name, _stream)

                if arc_res_name.startswith('/'):
                    add_entry(arc_res_name[1:], full_name=full_arc_res_name)

    for root, dirs, files in os.walk(content_dir, topdown=False):
        for file_name in files:
            host_path = os.path.join(root, file_name)
            res_name = os.path.relpath(host_path, content_dir)
            with open(host_path, "rb") as f:
                handle_file(res_name, full_name=res_name, stream=f)

    return crc32_to_name_map

def write_csv(file, header, rows) -> None:
    if not file:
        return
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(rows)

def main() -> None:
    args = parse_args()
    content_dir = args.content_dir

    crc32_map_bytes, name_map_bytes = read_rstb(content_dir, args.be)
    crc32_to_name_map = make_crc32_to_name_map(content_dir)

    entries: typing.List[typing.Tuple[int, str, str, int]] = []

    if crc32_map_bytes:
        for i in range(int(len(crc32_map_bytes) / 8)):
            crc32 = _read_u32(crc32_map_bytes, 8*i + 0, args.be)
            size = _read_u32(crc32_map_bytes, 8*i + 4, args.be)
            names = crc32_to_name_map.get(crc32, ("(unknown)", "(none)"))
            entries.append((crc32, names[0], names[1], size))

    if name_map_bytes:
        for i in range(int(len(name_map_bytes) / 132)):
            name = _read_string(name_map_bytes, 132*i + 0, args.be, 128)
            size = _read_u32(name_map_bytes, 132*i + 128, args.be)
            entries.append((crc32, name, "(none)", size))

    write_csv(args.csv, ["Hash", "Name", "Size"], entries)

if __name__ == "__main__":
    main()

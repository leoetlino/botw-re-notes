#!/usr/bin/env python3
# Copyright 2018 leoetlino <leo@leolam.fr>
# Licensed under MIT

import argparse
import binascii
import csv
import os
import sys
import typing

import rstb
import sarc
import wszst_yaz0

def parse_args():
    parser = argparse.ArgumentParser(description='Parses a RSTB (Resource Size TaBle) file.')
    parser.add_argument('content_dir', help='Path to a Breath of the Wild content root')
    parser.add_argument('--aoc', help='Path to a Breath of the Wild AoC root')
    parser.add_argument('-b', '--be', action='store_true', help='Use big endian. Defaults to false.')
    parser.add_argument('--csv', type=argparse.FileType('w'), nargs='?',
                        help='Path to output CSV for size information')
    args = parser.parse_args()

    if not os.path.isdir(args.content_dir):
        sys.stderr.write("%s is not actually a dir\n" % args.content_dir)
        sys.exit(1)

    if args.aoc and not os.path.isdir(args.aoc):
        sys.stderr.write("%s is not actually a dir\n" % args.aoc)
        sys.exit(1)

    return args

def read_rstb(content_dir: str, be: bool) -> rstb.ResourceSizeTable:
    with open("%s/System/Resource/ResourceSizeTable.product.srsizetable" % content_dir, "rb") as file:
        buf = wszst_yaz0.decompress(file.read())
        return rstb.ResourceSizeTable(buf, be)

def get_name_and_extension(path: str):
    res_name_without_ext, ext = os.path.splitext(path)
    return (res_name_without_ext, ext[1:]) # get rid of the leading dot in extension

Crc32ToNameMap = typing.Dict[int, typing.Tuple[str, str]]
def make_crc32_to_name_map(crc32_to_name_map: Crc32ToNameMap, content_dir: str, prefix: str) -> None:
    def add_entry(name: str, full_name: str) -> None:
        game_name = prefix + name
        crc32 = binascii.crc32(game_name.encode())
        if crc32 in crc32_to_name_map:
            return
        print("%08x -> (%s, %s)" % (crc32, game_name, full_name))
        crc32_to_name_map[crc32] = (game_name, full_name)

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

def write_csv(file, header, rows) -> None:
    if not file:
        return
    writer = csv.writer(file)
    writer.writerow(header)
    writer.writerows(rows)

def main() -> None:
    args = parse_args()
    content_dir = args.content_dir

    table = read_rstb(content_dir, args.be)
    crc32_to_name_map: Crc32ToNameMap = dict()
    make_crc32_to_name_map(crc32_to_name_map, content_dir, "")
    if args.aoc:
        make_crc32_to_name_map(crc32_to_name_map, args.aoc, "Aoc/0010/")

    entries: typing.List[typing.Tuple[str, str, str, int]] = []

    for crc32, size in table.crc32_map.items():
        names = crc32_to_name_map.get(crc32, ("(unknown)", "(unknown)"))
        entries.append(("0x%08x" % crc32, names[0], names[1], size))

    for name, size in table.name_map.items():
        entries.append(("0x%08x" % binascii.crc32(name.encode()), name, "(unknown)", size))

    write_csv(args.csv, ["Hash", "Name", "Full path", "Size"], entries)

if __name__ == "__main__":
    main()

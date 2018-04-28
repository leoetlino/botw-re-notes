#!/usr/bin/env python3
# Copyright 2018 leoetlino <leo@leolam.fr>
# Licensed under MIT

import logging
import struct
import typing

NULL_TERMINATOR = b'\x00'

def _get_unpack_endian_character(big_endian: bool):
    return '>' if big_endian else '<'

def _uint16(data: bytes, offset: int, be: bool) -> int:
    return struct.unpack_from(_get_unpack_endian_character(be) + 'H', data, offset)[0]

def _uint24(data: bytes, offset: int, be: bool) -> int:
    if be:
        return struct.unpack('>I', NULL_TERMINATOR + data[offset:offset+3])[0]
    return struct.unpack('<I', data[offset:offset+3] + NULL_TERMINATOR)[0]

def _uint32(data: bytes, offset: int, be: bool) -> int:
    return struct.unpack_from(_get_unpack_endian_character(be) + 'I', data, offset)[0]

def _string(data: bytes, offset: int) -> str:
    end = data.find(NULL_TERMINATOR, offset)
    return data[offset:end].decode('utf-8')

def _align_up(value: int, size: int) -> int:
    return value + (size - value % size) % size

class Byml:
    """A simple BYMLv2 parser that handles both big endian and little endian documents."""

    def __init__(self, data: bytes) -> None:
        self._data = data

        magic = self._data[0:2]
        if magic == b'BY':
            self._be = True
        elif magic == b'YB':
            self._be = False
        else:
            raise ValueError("Invalid magic: %s (expected 'BY' or 'YB')" % magic)

        version = _uint16(self._data, 2, self._be)
        if version != 2:
            raise ValueError("Invalid version: %u (expected 2)" % version)

        self._node_name_array_offset = _uint32(self._data, 4, self._be)
        self._string_array_offset = _uint32(self._data, 8, self._be)
        self._root_node_offset = _uint32(self._data, 12, self._be)

        self._node_name_array = self._parse_string_array(self._node_name_array_offset)
        if self._string_array_offset != 0:
            self._string_array = self._parse_string_array(self._string_array_offset)

    def parse(self):
        """Parse the BYML and get the root node with all children."""
        node_type = self._data[self._root_node_offset]
        if node_type != 0xc0 and node_type != 0xc1:
            raise ValueError("Invalid root node: expected array or dict, got type 0x%x" % node_type)
        return self._parse_node(node_type, self._root_node_offset)

    def _parse_string_array(self, offset) -> typing.List[str]:
        if self._data[offset] != 0xc2:
            raise ValueError("Invalid node type: 0x%x (expected 0xc2)" % self._data[offset])

        array = list()
        size = _uint24(self._data, offset + 1, self._be)
        for i in range(size):
            string_offset = offset + _uint32(self._data, offset + 4 + 4*i, self._be)
            array.append(_string(self._data, string_offset))
        return array

    def _parse_node(self, node_type, value):
        logging.info("Parsing node with type=0x%x value=0x%08x" % (node_type, value))
        if node_type == 0xa0:
            return self._parse_string_node(value)
        if node_type == 0xc0:
            return self._parse_array_node(value)
        if node_type == 0xc1:
            return self._parse_dict_node(value)
        if node_type == 0xd0:
            return self._parse_bool_node(value)
        if node_type == 0xd1:
            return self._parse_s32_node(value)
        if node_type == 0xd2:
            return self._parse_f32_node(value)
        if node_type == 0xd3:
            return self._parse_crc32_node(value)
        raise ValueError("Unknown node type: 0x%x" % node_type)

    def _parse_string_node(self, value: int) -> str:
        return self._string_array[value]

    def _parse_array_node(self, offset: int) -> list:
        size = _uint24(self._data, offset + 1, self._be)
        logging.info("Parsing array node with %u entries" % size)
        array: list = list()
        value_array_offset: int = offset + _align_up(size, 4) + 4
        for i in range(size):
            node_type = self._data[offset + 4 + i]
            value = _uint32(self._data, value_array_offset + 4*i, self._be)
            array.append(self._parse_node(node_type, value))
        return array

    def _parse_dict_node(self, offset: int) -> dict:
        size = _uint24(self._data, offset + 1, self._be)
        logging.info("Parsing dict node with %u entries" % size)
        result: dict = dict()
        for i in range(size):
            entry_offset: int = offset + 4 + 8*i
            string_index: int = _uint24(self._data, entry_offset + 0, self._be)
            name: str = self._node_name_array[string_index]

            node_type = self._data[entry_offset + 3]
            value = _uint32(self._data, entry_offset + 4, self._be)
            result[name] = self._parse_node(node_type, value)

        return result

    def _parse_bool_node(self, value: int) -> bool:
        return value != 0

    def _parse_s32_node(self, value: int) -> int:
        return struct.unpack('@i', struct.pack('@I', value))[0]

    def _parse_f32_node(self, value: int) -> float:
        return struct.unpack('@f', struct.pack('@I', value))[0]

    def _parse_crc32_node(self, value: int) -> int:
        return value

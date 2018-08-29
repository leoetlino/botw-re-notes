#!/usr/bin/env python3
import argparse
import enum
import mmap
import struct
import sys
import yaml

MAIN_MODULE_VADDR = 0x08007000 # for 1.0.0
# MAIN_MODULE_VADDR = 0x08005000 # for 1.5.0
HEAP_VADDR = 0x108000000
IDA_EA_BASE = 0x7100000000

# for 1.0.0
ROOT_HEAPS = 0x71022D8A40 - IDA_EA_BASE + MAIN_MODULE_VADDR

def read_bytes(ptr: int, count: int, module, heap) -> bytes:
    if ptr >= HEAP_VADDR:
        return heap[ptr-HEAP_VADDR:ptr-HEAP_VADDR+count]
    if ptr >= MAIN_MODULE_VADDR:
        return module[ptr-MAIN_MODULE_VADDR:ptr-MAIN_MODULE_VADDR+count]
    assert False, f'Bad pointer: {ptr}'

def u16(ptr: int, module, heap) -> int:
    return struct.unpack('<H', read_bytes(ptr, 2, module, heap))[0]
def u32(ptr: int, module, heap) -> int:
    return struct.unpack('<I', read_bytes(ptr, 4, module, heap))[0]
def s32(ptr: int, module, heap) -> int:
    return struct.unpack('<i', read_bytes(ptr, 4, module, heap))[0]
def u64(ptr: int, module, heap) -> int:
    return struct.unpack('<Q', read_bytes(ptr, 8, module, heap))[0]
_NUL_CHAR = b'\x00'
def string(ptr: int, module, heap) -> str:
    string_ptr = u64(ptr, module, heap)
    string = b''
    i = 0
    while True:
        c = read_bytes(string_ptr + i, 1, module, heap)
        if c == _NUL_CHAR:
            break
        string += c
        i += 1
    return string.decode()

class Address(int):
    pass

def parse_expheap(ptr: int, module, heap) -> dict:
    info: dict = {}

    free_size = 0
    nxt = u64(ptr + 0xe0 + 8, module, heap)
    if nxt != ptr + 0xe0:
        while True:
            free_size += u64(nxt + 0x18, module, heap)
            nxt = u64(nxt + 8, module, heap)
            if nxt == ptr + 0xe0:
                break

    info['free_size'] = free_size
    info['free_list_size'] = u32(ptr + 0xf0, module, heap)
    info['use_list_size'] = u32(ptr + 0x108, module, heap)

    def get_max_allocatable_size() -> int: # 0x7100B066EC
        nxt = u64(ptr + 0xe0 + 8, module, heap)
        if nxt == ptr + 0xe0:
            return 0
        v10 = 0
        while True:
            v11 = u64(nxt + 0x18, module, heap)
            if v11 >= 8 and (not v10 or u64(v10 + 0x18, module, heap) < v11):
                v10 = nxt
            nxt = u64(nxt + 8, module, heap)
            if nxt == ptr + 0xe0:
                break
        if not v10:
            return 0
        return u64(v10 + 0x18, module, heap)

    info['max_allocatable_size'] = get_max_allocatable_size()

    return info

def parse_dualheap(ptr: int, module, heap) -> dict:
    info: dict = {}
    info.update(parse_expheap(ptr, module, heap))
    return info

def parse_frameheap(ptr: int, module, heap) -> dict:
    info: dict = {}
    return info

def parse_dualframeheap(ptr: int, module, heap) -> dict:
    info: dict = {}
    return info

def parse_unitheap(ptr: int, module, heap) -> dict:
    info: dict = {}
    return info

# for 1.0.0
HEAP_CLASSES = {
    0x71021B6548: ('ExpHeap', parse_expheap),
    0x71021FB260: ('DualHeap', parse_dualheap),
    0x71021B6668: ('FrameHeap', parse_frameheap),
    0x71021FB148: ('DualFrameHeap', parse_dualframeheap),
    0x710221DB60: ('UnitHeap', parse_unitheap),
}

def parse_heap(ptr: int, module, heap) -> dict:
    vtable = u64(ptr, module, heap)
    name = string(ptr + 0x20 + 8, module, heap)
    size = u64(ptr + 0x40, module, heap)
    parent = u64(ptr + 0x48, module, heap)
    parent_name = string(parent + 0x20 + 8, module, heap) if parent else None
    num_children = u32(ptr + 0x60, module, heap)

    info: dict = {}
    info['name'] = name
    info['addr'] = Address(ptr)
    info['parent'] = parent_name
    info['size'] = size
    info['type'] = 'Heap'
    class_info = HEAP_CLASSES.get(vtable - MAIN_MODULE_VADDR + IDA_EA_BASE, None)
    if class_info is not None:
        info['type'] = class_info[0]
        info.update(class_info[1](ptr, module, heap))
    else:
        info['type'] = f'unknown vtable @ {vtable - MAIN_MODULE_VADDR + IDA_EA_BASE:x}'
    info['children'] = []

    child_node = u64(ptr + 0x58, module, heap)
    if child_node == ptr + 0x50:
        return info

    child = child_node - 0x68
    for i in range(num_children):
        info['children'].append(parse_heap(child, module, heap))
        sibling = u64(child + 0x70, module, heap) - 0x68
        child = sibling

    return info

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('main_module_dump', help='Path to a memory dump of the main module (.text + .data + .bss)')
    parser.add_argument('process_heap_dump', help='Path to a memory dump of the process heap')
    args = parser.parse_args()

    heap_info: dict = {}

    with open(args.main_module_dump, 'rb') as mmf, open(args.process_heap_dump, 'rb') as phf, \
    mmap.mmap(mmf.fileno(), 0, access=mmap.ACCESS_READ) as module, \
    mmap.mmap(phf.fileno(), 0, access=mmap.ACCESS_READ) as heap:
        root_heap_array_size = u32(ROOT_HEAPS, module, heap)
        root_heap_array_capacity = u32(ROOT_HEAPS + 4, module, heap)
        assert root_heap_array_size == 1
        heap_info['root_heap_array'] = {}
        heap_info['root_heap_array']['addr'] = Address(ROOT_HEAPS)
        heap_info['root_heap_array']['size'] = root_heap_array_size
        heap_info['root_heap_array']['capacity'] = root_heap_array_capacity

        root_heap_array_ptr = u64(ROOT_HEAPS + 8, module, heap)
        root_heap_ptr = u64(root_heap_array_ptr, module, heap)
        heap_info['root_heap'] = parse_heap(root_heap_ptr, module, heap)

    print_info(heap_info)

def print_info(heap_info) -> None:
    # From PyYAML: https://github.com/yaml/pyyaml/blob/a9c28e0b52/lib3/yaml/representer.py
    # with the sorting code removed.
    def represent_mapping(dumper, tag, mapping, flow_style=None):
        value = [] # type: ignore
        node = yaml.MappingNode(tag, value, flow_style=flow_style)
        best_style = True
        if hasattr(mapping, 'items'):
            mapping = list(mapping.items())
        for item_key, item_value in mapping:
            node_key = dumper.represent_data(item_key)
            node_value = dumper.represent_data(item_value)
            if not (isinstance(node_key, yaml.ScalarNode) and not node_key.style):
                best_style = False
            if not (isinstance(node_value, yaml.ScalarNode) and not node_value.style):
                best_style = False
            value.append((node_key, node_value))
        if flow_style is None:
            if dumper.default_flow_style is not None:
                node.flow_style = dumper.default_flow_style
            else:
                node.flow_style = best_style
        return node

    yaml.add_representer(Address, lambda d, p: d.represent_scalar('tag:yaml.org,2002:int', f'0x{p:x}'), Dumper=yaml.CSafeDumper)
    yaml.add_representer(dict, lambda d, m: represent_mapping(d, 'tag:yaml.org,2002:map', m), Dumper=yaml.CSafeDumper)
    yaml.dump(heap_info, sys.stdout, Dumper=yaml.CSafeDumper, allow_unicode=True, encoding='utf-8', indent=4)

if __name__ == '__main__':
    main()

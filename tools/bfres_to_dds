#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# BFRES Tool
# Version 4.1
# Copyright © 2017 Stella/AboodXD

# This file is part of BFRES Tool.

# BFRES Tool is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# BFRES Tool is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""bfres_to_dds.py: Convert bfres to DDS."""

import os, sys, struct

try:
    import addrlib_cy as addrlib
except ImportError:
    import addrlib

import dds

try:
    import form_conv_cy as form_conv
except ImportError:
    import form_conv

formats = {0x00000001: 'GX2_SURFACE_FORMAT_TC_R8_UNORM',
           0x00000002: 'GX2_SURFACE_FORMAT_TC_R4_G4_UNORM',
           0x00000007: 'GX2_SURFACE_FORMAT_TC_R8_G8_UNORM',
           0x00000008: 'GX2_SURFACE_FORMAT_TCS_R5_G6_B5_UNORM',
           0x0000000a: 'GX2_SURFACE_FORMAT_TC_R5_G5_B5_A1_UNORM',
           0x0000000b: 'GX2_SURFACE_FORMAT_TC_R4_G4_B4_A4_UNORM',
           0x00000019: 'GX2_SURFACE_FORMAT_TCS_R10_G10_B10_A2_UNORM',
           0x0000001a: 'GX2_SURFACE_FORMAT_TCS_R8_G8_B8_A8_UNORM',
           0x0000041a: 'GX2_SURFACE_FORMAT_TCS_R8_G8_B8_A8_SRGB',
           0x00000031: 'GX2_SURFACE_FORMAT_T_BC1_UNORM',
           0x00000431: 'GX2_SURFACE_FORMAT_T_BC1_SRGB',
           0x00000032: 'GX2_SURFACE_FORMAT_T_BC2_UNORM',
           0x00000432: 'GX2_SURFACE_FORMAT_T_BC2_SRGB',
           0x00000033: 'GX2_SURFACE_FORMAT_T_BC3_UNORM',
           0x00000433: 'GX2_SURFACE_FORMAT_T_BC3_SRGB',
           0x00000034: 'GX2_SURFACE_FORMAT_T_BC4_UNORM',
           0x00000234: 'GX2_SURFACE_FORMAT_T_BC4_SNORM',
           0x00000035: 'GX2_SURFACE_FORMAT_T_BC5_UNORM',
           0x00000235: 'GX2_SURFACE_FORMAT_T_BC5_SNORM'
           }

BCn_formats = [0x31, 0x431, 0x32, 0x432, 0x33, 0x433, 0x34, 0x234, 0x35, 0x235]

tileModes = {0x00: 'GX2_TILE_MODE_DEFAULT',
             0x01: 'GX2_TILE_MODE_LINEAR_ALIGNED',
             0x02: 'GX2_TILE_MODE_1D_TILED_THIN1',
             0x03: 'GX2_TILE_MODE_1D_TILED_THICK',
             0x04: 'GX2_TILE_MODE_2D_TILED_THIN1',
             0x05: 'GX2_TILE_MODE_2D_TILED_THIN2',
             0x06: 'GX2_TILE_MODE_2D_TILED_THIN4',
             0x07: 'GX2_TILE_MODE_2D_TILED_THICK',
             0x08: 'GX2_TILE_MODE_2B_TILED_THIN1',
             0x09: 'GX2_TILE_MODE_2B_TILED_THIN2',
             0x0a: 'GX2_TILE_MODE_2B_TILED_THIN4',
             0x0b: 'GX2_TILE_MODE_2B_TILED_THICK',
             0x0c: 'GX2_TILE_MODE_3D_TILED_THIN1',
             0x0d: 'GX2_TILE_MODE_3D_TILED_THICK',
             0x0e: 'GX2_TILE_MODE_3B_TILED_THIN1',
             0x0f: 'GX2_TILE_MODE_3B_TILED_THICK',
             0x10: 'GX2_TILE_MODE_LINEAR_SPECIAL'}

formats2 = {0x00000001: 'L8',
            0x00000002: 'L4A4 / LA4',
            0x00000007: 'L8A8 / LA8',
            0x00000008: 'R5G6B5 / RGB565',
            0x0000000a: 'A1RGB5 / A1BGR5',
            0x0000000b: 'ARGB4 / ABGR4',
            0x00000019: 'A2RGB10 / A2BGR10',
            0x0000001a: 'ARGB8 / ABGR8',
            0x0000041a: 'ARGB8 / ABGR8',
            0x00000031: 'BC1 / DXT1',
            0x00000431: 'BC1 / DXT1',
            0x00000032: 'BC2 / DXT3',
            0x00000432: 'BC2 / DXT3',
            0x00000033: 'BC3 / DXT5',
            0x00000433: 'BC3 / DXT5',
            0x00000034: 'BC4U / ATI1',
            0x00000234: 'BC4S / ATI1',
            0x00000035: 'BC5U / ATI2',
            0x00000235: 'BC5S / ATI2'
            }

class groups():
    pass

def find_name(f, name_pos):
    name = b""
    char = f[name_pos:name_pos + 1]
    i = 1

    while char != b"\x00":
        name += char
        if name_pos + i == len(f): break  # Prevent it from looping forever

        char = f[name_pos + i:name_pos + i + 1]
        i += 1

    return(name.decode("utf-8"))

class GX2Surface(struct.Struct):
    def __init__(self):
        super().__init__('>16I')

    def data(self, data, pos):
        (self.dim,
         self.width,
         self.height,
         self.depth,
         self.numMips,
         self.format_,
         self.aa,
         self.use,
         self.imageSize,
         self.imagePtr,
         self.mipSize,
         self.mipPtr,
         self.tileMode,
         self.swizzle,
         self.alignment,
         self.pitch) = self.unpack_from(data, pos)

def FTEXtoDDS(ftex_pos, f, name, folder):
    ftex = f[ftex_pos:ftex_pos+0xC0]

    pos = 4

    surface = GX2Surface()
    surface.data(ftex, pos)

    pos += surface.size

    format_ = surface.format_

    if format_ in formats:
        if surface.numMips > 14:
            print('')
            print(name)
            print("Number of mipmaps exceeded 13")
            return 0, 0

        mipOffsets = []
        for i in range(13):
            mipOffsets.append(ftex[i * 4 + pos] << 24 | ftex[i * 4 + 1 + pos] << 16 | ftex[i * 4 + 2 + pos] << 8 | ftex[i * 4 + 3 + pos])

        pos += 68

        compSel = []
        for i in range(4):
            comp = ftex[pos + i]
            if comp == 4: # Sorry, but this is unsupported.
                comp = i
            compSel.append(comp)

        dataSize = surface.imageSize
        mipSize = surface.mipSize

        data_pos = struct.unpack(">I", ftex[0xB0:0xB4])[0] + ftex_pos + 0xB0
        mip_pos = struct.unpack(">I", ftex[0xB4:0xB8])[0]

        data = f[data_pos:data_pos+dataSize]

        if not (mip_pos and mipSize):
            mipData = b""
        else:
            mip_pos += ftex_pos + 0xB4
            mipData = f[mip_pos:mip_pos+mipSize]

        numMips = surface.numMips
        width = surface.width
        height = surface.height
        depth = surface.depth
        dim = surface.dim
        aa = surface.aa
        tileMode = surface.tileMode
        swizzle_ = surface.swizzle
        bpp = addrlib.surfaceGetBitsPerPixel(format_) >> 3

        if format_ in BCn_formats:
            realSize = ((width + 3) >> 2) * ((height + 3) >> 2) * bpp
        else:
            realSize = width * height * bpp

        surfOut = addrlib.getSurfaceInfo(format_, width, height, depth, dim, tileMode, aa, 0)

        if aa:
            print('')
            print(name)
            print("Unsupported AA mode")
            return 0, 0

        if format_ == 0x1a or format_ == 0x41a:
            format__ = 28
        elif format_ == 0x19:
            format__ = 24
        elif format_ == 0x8:
            format__ = 85
        elif format_ == 0xa:
            format__ = 86
        elif format_ == 0xb:
            format__ = 115
        elif format_ == 0x1:
            format__ = 61
        elif format_ == 0x7:
            format__ = 49
        elif format_ == 0x2:
            format__ = 112
        elif format_ == 0x31 or format_ == 0x431:
            format__ = "BC1"
        elif format_ == 0x32 or format_ == 0x432:
            format__ = "BC2"
        elif format_ == 0x33 or format_ == 0x433:
            format__ = "BC3"
        elif format_ == 0x34:
            format__ = "BC4U"
        elif format_ == 0x234:
            format__ = "BC4S"
        elif format_ == 0x35:
            format__ = "BC5U"
        elif format_ == 0x235:
            format__ = "BC5S"

        if surfOut.depth != 1:
            print('')
            print(name)
            print("Unsupported depth")
            return 0, 0

        result = []
        for level in range(numMips):
            if level != 0:
                if level == 1:
                    mipOffset = mipOffsets[level - 1] - surfOut.surfSize
                else:
                    mipOffset = mipOffsets[level - 1]

                surfOut = addrlib.getSurfaceInfo(format_, width, height, depth, dim, tileMode, aa, level)

                data = mipData[mipOffset:mipOffset + surfOut.surfSize]

            deswizzled = addrlib.deswizzle(max(1, width >> level), max(1, height >> level), surfOut.height, format_, surfOut.tileMode, swizzle_, surfOut.pitch, surfOut.bpp, data)

            if format_ in BCn_formats:
                size = ((max(1, width >> level) + 3) >> 2) * ((max(1, height >> level) + 3) >> 2) * bpp
            else:
                size = max(1, width >> level) * max(1, height >> level) * bpp

            if format_ == 0xa:
                data = form_conv.toDDSrgb5a1(deswizzled[:size])

            elif format_ == 0xb:
                data = form_conv.toDDSrgba4(deswizzled[:size])

            else:
                data = deswizzled[:size]

            result.append(data)

        hdr = dds.generateHeader(numMips, width, height, format__, compSel, realSize, format_ in BCn_formats)

        with open(folder + "/" + name + ".dds", "wb") as output:
            output.write(hdr)
            for data in result:
                output.write(data)

        return format_, numMips

    else:
        print('')
        print(name)
        print("Unsupported format: " + hex(format_))
        return format_, 0

def get_curr_mip_off_size(width, height, bpp, curr_level, compressed):
    off = 0

    for i in range(curr_level - 1):
        level = i + 1
        if compressed:
            off += ((max(1, width >> level) + 3) >> 2) * ((max(1, height >> level) + 3) >> 2) * bpp
        else:
            off += max(1, width >> level) * max(1, height >> level) * bpp

    if compressed:
        size = ((max(1, width >> curr_level) + 3) >> 2) * ((max(1, height >> curr_level) + 3) >> 2) * bpp
    else:
        size = max(1, width >> curr_level) * max(1, height >> curr_level) * bpp

    return off, size

def writeGX2Surface_Data(f, tileMode, swizzle_, SRGB):
    width, height, format_, fourcc, dataSize, compSel, numMips, data = dds.readDDS(f, SRGB)

    if 0 in [width, dataSize] and data == []:
        return False

    if format_ not in formats:
        print("Unsupported DDS format!")
        return b'', []

    if numMips > 13:
        print("Invalid number of mipmaps!")
        return b'', []

    imageData = data[:dataSize]
    mipData = data[dataSize:]
    numMips += 1

    bpp = addrlib.surfaceGetBitsPerPixel(format_) >> 3

    alignment = 512 * bpp

    surfOut = addrlib.getSurfaceInfo(format_, width, height, 1, 1, tileMode, 0, 0)

    pitch = surfOut.pitch

    if surfOut.depth != 1:
        print("Unsupported depth!")
        return b'', []

    if tileMode in [1, 2, 3, 16]:
        s = 0
    else:
        s = 0xd0000

    s |= swizzle_

    swizzled_data = []
    imageSize = 0
    mipSize = 0
    mipOffsets = []
    for i in range(numMips):
        if i == 0:
            data = imageData

            imageSize = surfOut.surfSize
        else:
            offset, dataSize = get_curr_mip_off_size(width, height, bpp, i, format_ in BCn_formats)

            data = mipData[offset:offset+dataSize]

            surfOut = addrlib.getSurfaceInfo(format_, width, height, 1, 1, tileMode, 0, i)

        padSize = surfOut.surfSize - dataSize
        data += padSize * b"\x00"

        if i != 0:
            if i == 1:
                mipOffsets.append(imageSize)
            else:
                mipOffsets.append(mipSize)

            mipSize += len(data)

        swizzled_data.append(addrlib.swizzle(max(1, width >> i), max(1, height >> i), surfOut.height, format_, surfOut.tileMode, s, surfOut.pitch, surfOut.bpp, data))

    gx2surf_struct = GX2Surface()
    gx2surf = gx2surf_struct.pack(1, width, height, 1, numMips, format_, 0, 1, imageSize, 0, mipSize, 0, tileMode, s, alignment, pitch)

    if numMips > 1:
        i = 0
        for offset in mipOffsets:
            gx2surf += offset.to_bytes(4, 'big')
            i += 1
        for z in range(14 - i):
            gx2surf += 0 .to_bytes(4, 'big')
    else:
        gx2surf += b"\x00" * 56

    gx2surf += numMips.to_bytes(4, 'big')
    gx2surf += b"\x00" * 4
    gx2surf += 1 .to_bytes(4, 'big')

    for value in compSel:
        gx2surf += value.to_bytes(1, 'big')

    gx2surf += b"\x00" * 20

    return gx2surf, swizzled_data

def DDStoBFRES(ftex_pos, dds, bfres):
    with open(bfres, "rb") as inf:
        inb = inf.read()
        inf.close()

    format_ = struct.unpack(">I", inb[ftex_pos+0x18:ftex_pos+0x1C])[0]
    tileMode = struct.unpack(">I", inb[ftex_pos+0x34:ftex_pos+0x38])[0]
    swizzle = struct.unpack(">I", inb[ftex_pos+0x38:ftex_pos+0x3C])[0] & 0xF00

    gx2surface, result = writeGX2Surface_Data(dds, tileMode, swizzle, (format_ & 0x400) == 0x400)

    if gx2surface == b'' or result == []:
        return

    dataSize = struct.unpack(">I", gx2surface[0x20:0x24])[0]
    dataSize2 = struct.unpack(">I", inb[ftex_pos+0x24:ftex_pos+0x28])[0]

    mipSize = struct.unpack(">I", gx2surface[0x28:0x2C])[0]
    mipSize2 = struct.unpack(">I", inb[ftex_pos+0x2C:ftex_pos+0x30])[0]

    if inb[:4] != b"FRES":
        print("Invalid BFRES header!")

    elif dataSize > dataSize2:
        print("Data size mismatch")

    elif mipSize > mipSize2:
        print("Mipmap size mismatch")

    else:
        inb = bytearray(inb)

        inb[ftex_pos+0x04:ftex_pos+0xA0] = gx2surface

        data_pos = struct.unpack(">I", bytes(inb[ftex_pos+0xB0:ftex_pos+0xB4]))[0] + ftex_pos + 0xB0
        mip_pos = struct.unpack(">I", bytes(inb[ftex_pos+0xB4:ftex_pos+0xB8]))[0]

        inb[data_pos:data_pos+dataSize] = result[0]

        if mip_pos == 0:
            pass
        else:
            mip_pos += ftex_pos + 0xB4
            inb[mip_pos:mip_pos+mipSize] = b"".join(result[1:])

        with open(bfres, "wb") as output:
            output.write(inb)
            output.close()

        print("Done!")

def main():
    filename = sys.argv[1]

    with open(filename, "rb") as inf:
        inb = inf.read()
        inf.close()

    if inb[:4] != b"FRES":
        print("Invalid BFRES header!")
    else:
        group = groups()
        group.pos = struct.unpack(">I", inb[0x24:0x28])[0]

        if group.pos == 0:
            print("No textures found in this BFRES file!")
        else:
            group.pos += 0x24
            group.file = struct.unpack(">I", inb[group.pos+4:(group.pos+4)+4])[0]

            group.name_pos = []
            group.name = []
            group.data_pos = []

            for i in range(group.file + 1):
                group.name_pos.append(struct.unpack(">I", inb[group.pos+8+(0x10*i)+8:(group.pos+8+(0x10*i)+8)+4])[0])
                group.data_pos.append(struct.unpack(">I", inb[group.pos+8+(0x10*i)+12:(group.pos+8+(0x10*i)+12)+4])[0])


                if group.data_pos[i] == 0:
                    group.name.append("")
                else:
                    group.name_pos[i] += group.pos + 8 + (0x10*i) + 8
                    group.data_pos[i] += group.pos + 8 + (0x10*i) + 12
                    group.name.append(find_name(inb, group.name_pos[i]))

            folder = os.path.dirname(os.path.abspath(filename))

            for i in range(group.file):
                ftex_pos = group.data_pos[i + 1]
                name = group.name[i + 1]
                if os.path.isfile(folder + "\\" + name + ".dds"):
                    format_ = struct.unpack(">I", inb[ftex_pos+0x18:ftex_pos+0x1C])[0]
                    numMips = struct.unpack(">I", inb[ftex_pos+0x14:ftex_pos+0x18])[0]

                else:
                    format_, numMips = FTEXtoDDS(ftex_pos, inb, name, folder)

            print("Done!")

if __name__ == '__main__': main()

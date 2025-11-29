import struct
import zlib

def create_png(filename, width, height):
    with open(filename, 'wb') as f:
        # PNG signature
        f.write(b'\x89PNG\r\n\x1a\n')
        # IHDR chunk - type 6 means RGBA (with alpha)
        ihdr = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
        f.write(struct.pack('>I', len(ihdr)) + b'IHDR' + ihdr)
        crc = 0xffffffff
        for byte in b'IHDR' + ihdr:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ 0xedb88320 if crc & 1 else crc >> 1
        f.write(struct.pack('>I', crc ^ 0xffffffff))
        # IDAT chunk - purple color with full alpha (RGBA)
        idat_data = b''
        for y in range(height):
            idat_data += b'\x00' + b'\x80\x00\x80\xff' * width
        compressed = zlib.compress(idat_data)
        f.write(struct.pack('>I', len(compressed)) + b'IDAT' + compressed)
        crc = 0xffffffff
        for byte in b'IDAT' + compressed:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ 0xedb88320 if crc & 1 else crc >> 1
        f.write(struct.pack('>I', crc ^ 0xffffffff))
        # IEND chunk
        f.write(b'\x00\x00\x00\x00IEND\xaeB`\x82')

create_png('src-tauri/icons/icon.png', 256, 256)
print('Icon created successfully')

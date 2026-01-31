import struct

class BinaryReader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def seek(self, offset: int):
        if offset < 0 or offset > len(self.data):
            raise ValueError(f"Offset {offset} is out of bounds (0-{len(self.data)})")
        self.offset = offset

    def tell(self) -> int:
        return self.offset

    def read(self, size: int) -> bytes:
        if self.offset + size > len(self.data):
            raise ValueError(f"Attempted to read {size} bytes at offset {self.offset}, but only {len(self.data) - self.offset} bytes remain.")
        chunk = self.data[self.offset:self.offset + size]
        self.offset += size
        return chunk

    def read_u8(self) -> int:
        return struct.unpack("<B", self.read(1))[0]

    def read_u16(self) -> int:
        return struct.unpack("<H", self.read(2))[0]

    def read_u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def read_u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]

    def read_string(self, max_length: int = 256) -> str:
        """Reads a null-terminated string."""
        s = b""
        while len(s) < max_length:
            char = self.read(1)
            if char == b"\x00":
                break
            s += char
        return s.decode("ascii", errors="ignore")

    def read_fixed_string(self, length: int) -> str:
        """Reads a fixed-length string and strips null bytes."""
        return self.read(length).decode("ascii", errors="ignore").rstrip("\x00")

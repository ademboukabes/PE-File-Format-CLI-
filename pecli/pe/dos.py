from dataclasses import dataclass
from pecli.utils.reader import BinaryReader

@dataclass
class DOSHeader:
    magic: bytes  # MZ
    e_lfanew: int # Offset to NT Headers

    @classmethod
    def parse(cls, reader: BinaryReader) -> "DOSHeader":
        reader.seek(0)
        magic = reader.read(2)
        if magic != b"MZ":
            raise ValueError(f"Invalid DOS magic: {magic!r}")
        
        # e_lfanew is at offset 0x3C
        reader.seek(0x3C)
        e_lfanew = reader.read_u32()
        
        return cls(magic=magic, e_lfanew=e_lfanew)

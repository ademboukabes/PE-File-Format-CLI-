from dataclasses import dataclass
from typing import List
from pecli.utils.reader import BinaryReader

@dataclass
class SectionHeader:
    name: str
    virtual_size: int
    virtual_address: int
    size_of_raw_data: int
    pointer_to_raw_data: int
    pointer_to_relocations: int
    pointer_to_linenumbers: int
    number_of_relocations: int
    number_of_linenumbers: int
    characteristics: int

    @classmethod
    def parse(cls, reader: BinaryReader) -> "SectionHeader":
        return cls(
            name=reader.read_fixed_string(8),
            virtual_size=reader.read_u32(),
            virtual_address=reader.read_u32(),
            size_of_raw_data=reader.read_u32(),
            pointer_to_raw_data=reader.read_u32(),
            pointer_to_relocations=reader.read_u32(),
            pointer_to_linenumbers=reader.read_u32(),
            number_of_relocations=reader.read_u16(),
            number_of_linenumbers=reader.read_u16(),
            characteristics=reader.read_u32()
        )

def parse_sections(reader: BinaryReader, count: int, offset: int) -> List[SectionHeader]:
    reader.seek(offset)
    sections = []
    for _ in range(count):
        sections.append(SectionHeader.parse(reader))
    return sections

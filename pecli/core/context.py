from typing import List, Optional
from pecli.utils.reader import BinaryReader
from pecli.pe.dos import DOSHeader
from pecli.pe.headers import NTHeaders
from pecli.pe.sections import SectionHeader, parse_sections

class PEContext:
    def __init__(self, data: bytes):
        self.reader = BinaryReader(data)
        self.dos_header: Optional[DOSHeader] = None
        self.nt_headers: Optional[NTHeaders] = None
        self.sections: List[SectionHeader] = []

    def parse(self):
        self.dos_header = DOSHeader.parse(self.reader)
        self.nt_headers = NTHeaders.parse(self.reader, self.dos_header.e_lfanew)
        
        # Sections start immediately after the NT headers
        # Specifically, after Optional Header, which has variable size
        # Optional Header start + size of optional header (from File Header)
        # But wait, it's easier to just track where NTHeaders.parse finished
        section_offset = self.reader.tell()
        self.sections = parse_sections(
            self.reader, 
            self.nt_headers.file_header.number_of_sections,
            section_offset
        )

    def rva_to_offset(self, rva: int) -> Optional[int]:
        """Converts Relative Virtual Address (RVA) to file offset."""
        for section in self.sections:
            if section.virtual_address <= rva < section.virtual_address + section.virtual_size:
                return section.pointer_to_raw_data + (rva - section.virtual_address)
        return None

    def get_section_data(self, name: str) -> Optional[bytes]:
        for section in self.sections:
            if section.name == name:
                self.reader.seek(section.pointer_to_raw_data)
                return self.reader.read(section.size_of_raw_data)
        return None

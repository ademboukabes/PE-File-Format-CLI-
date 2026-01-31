from dataclasses import dataclass
from typing import Dict
from pecli.utils.reader import BinaryReader

@dataclass
class FileHeader:
    machine: int
    number_of_sections: int
    timestamp: int
    pointer_to_symbol_table: int
    number_of_symbols: int
    size_of_optional_header: int
    characteristics: int

    @classmethod
    def parse(cls, reader: BinaryReader) -> "FileHeader":
        return cls(
            machine=reader.read_u16(),
            number_of_sections=reader.read_u16(),
            timestamp=reader.read_u32(),
            pointer_to_symbol_table=reader.read_u32(),
            number_of_symbols=reader.read_u32(),
            size_of_optional_header=reader.read_u16(),
            characteristics=reader.read_u16(),
        )

@dataclass
class DataDirectory:
    virtual_address: int
    size: int

@dataclass
class OptionalHeader:
    magic: int
    major_linker_version: int
    minor_linker_version: int
    size_of_code: int
    size_of_initialized_data: int
    size_of_uninitialized_data: int
    address_of_entry_point: int
    base_of_code: int
    image_base: int
    section_alignment: int
    file_alignment: int
    major_operating_system_version: int
    minor_operating_system_version: int
    major_image_version: int
    minor_image_version: int
    major_subsystem_version: int
    minor_subsystem_version: int
    win32_version_value: int
    size_of_image: int
    size_of_headers: int
    check_sum: int
    subsystem: int
    dll_characteristics: int
    size_of_stack_reserve: int
    size_of_stack_commit: int
    size_of_heap_reserve: int
    size_of_heap_commit: int
    loader_flags: int
    number_of_rva_and_sizes: int
    data_directories: Dict[str, DataDirectory]

    @classmethod
    def parse(cls, reader: BinaryReader) -> "OptionalHeader":
        start_offset = reader.tell()
        magic = reader.read_u16()
        is_pe32_plus = magic == 0x20b

        header = cls(
            magic=magic,
            major_linker_version=reader.read_u8(),
            minor_linker_version=reader.read_u8(),
            size_of_code=reader.read_u32(),
            size_of_initialized_data=reader.read_u32(),
            size_of_uninitialized_data=reader.read_u32(),
            address_of_entry_point=reader.read_u32(),
            base_of_code=reader.read_u32(),
            image_base=reader.read_u64() if is_pe32_plus else reader.read_u32(),
            section_alignment=reader.read_u32(),
            file_alignment=reader.read_u32(),
            major_operating_system_version=reader.read_u16(),
            minor_operating_system_version=reader.read_u16(),
            major_image_version=reader.read_u16(),
            minor_image_version=reader.read_u16(),
            major_subsystem_version=reader.read_u16(),
            minor_subsystem_version=reader.read_u16(),
            win32_version_value=reader.read_u32(),
            size_of_image=reader.read_u32(),
            size_of_headers=reader.read_u32(),
            check_sum=reader.read_u32(),
            subsystem=reader.read_u16(),
            dll_characteristics=reader.read_u16(),
            size_of_stack_reserve=reader.read_u64() if is_pe32_plus else reader.read_u32(),
            size_of_stack_commit=reader.read_u64() if is_pe32_plus else reader.read_u32(),
            size_of_heap_reserve=reader.read_u64() if is_pe32_plus else reader.read_u32(),
            size_of_heap_commit=reader.read_u64() if is_pe32_plus else reader.read_u32(),
            loader_flags=reader.read_u32(),
            number_of_rva_and_sizes=reader.read_u32(),
            data_directories={}
        )

        directory_names = [
            "EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE",
            "CERTIFICATE_TABLE", "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE",
            "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE", "BOUND_IMPORT",
            "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER", "RESERVED"
        ]

        for i in range(header.number_of_rva_and_sizes):
            rva = reader.read_u32()
            size = reader.read_u32()
            if i < len(directory_names):
                header.data_directories[directory_names[i]] = DataDirectory(rva, size)
            else:
                header.data_directories[f"UNKNOWN_{i}"] = DataDirectory(rva, size)

        return header

@dataclass
class NTHeaders:
    signature: bytes # PE\0\0
    file_header: FileHeader
    optional_header: OptionalHeader

    @classmethod
    def parse(cls, reader: BinaryReader, offset: int) -> "NTHeaders":
        reader.seek(offset)
        signature = reader.read(4)
        if signature != b"PE\x00\x00":
            raise ValueError(f"Invalid NT signature: {signature!r}")
        
        file_header = FileHeader.parse(reader)
        optional_header = OptionalHeader.parse(reader)
        
        return cls(signature=signature, file_header=file_header, optional_header=optional_header)

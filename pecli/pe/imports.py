from dataclasses import dataclass
from typing import List, Optional
from pecli.utils.reader import BinaryReader
from pecli.core.context import PEContext

@dataclass
class ImportEntry:
    name: str
    hint: int

@dataclass
class ImportDescriptor:
    dll_name: str
    original_first_thunk: int
    time_date_stamp: int
    forwarder_chain: int
    name_rva: int
    first_thunk: int
    imports: List[ImportEntry]

def parse_imports(ctx: PEContext) -> List[ImportDescriptor]:
    import_table = ctx.nt_headers.optional_header.data_directories.get("IMPORT_TABLE")
    if not import_table or import_table.virtual_address == 0:
        return []

    descriptors = []
    offset = ctx.rva_to_offset(import_table.virtual_address)
    if offset is None:
        return []

    ctx.reader.seek(offset)
    
    while True:
        original_first_thunk = ctx.reader.read_u32()
        time_date_stamp = ctx.reader.read_u32()
        forwarder_chain = ctx.reader.read_u32()
        name_rva = ctx.reader.read_u32()
        first_thunk = ctx.reader.read_u32()

        if original_first_thunk == 0 and name_rva == 0:
            break

        # Save current position to return later
        current_pos = ctx.reader.tell()

        # Read DLL name
        dll_name_offset = ctx.rva_to_offset(name_rva)
        if dll_name_offset is not None:
            ctx.reader.seek(dll_name_offset)
            dll_name = ctx.reader.read_string()
        else:
            dll_name = "UNKNOWN"

        # Read imports (thunks)
        # We use OriginalFirstThunk (ILT) if available, otherwise FirstThunk (IAT)
        thunk_rva = original_first_thunk if original_first_thunk != 0 else first_thunk
        thunk_offset = ctx.rva_to_offset(thunk_rva)
        
        imports = []
        if thunk_offset is not None:
            ctx.reader.seek(thunk_offset)
            is_64bit = ctx.nt_headers.optional_header.magic == 0x20b
            
            while True:
                val = ctx.reader.read_u64() if is_64bit else ctx.reader.read_u32()
                if val == 0:
                    break
                
                # Check for ordinal import (highest bit set)
                ordinal_mask = 0x8000000000000000 if is_64bit else 0x80000000
                if val & ordinal_mask:
                    imports.append(ImportEntry(name=f"Ordinal_{val & 0xFFFF}", hint=0))
                else:
                    # RVA to Hint/Name table
                    name_thunk_offset = ctx.rva_to_offset(val & 0x7FFFFFFFFFFFFFFF if is_64bit else val & 0x7FFFFFFF)
                    if name_thunk_offset is not None:
                        # Remember position in thunk list
                        thunk_pos = ctx.reader.tell()
                        ctx.reader.seek(name_thunk_offset)
                        hint = ctx.reader.read_u16()
                        name = ctx.reader.read_string()
                        imports.append(ImportEntry(name=name, hint=hint))
                        ctx.reader.seek(thunk_pos)
                    else:
                        imports.append(ImportEntry(name="UNKNOWN", hint=0))

        descriptors.append(ImportDescriptor(
            dll_name=dll_name,
            original_first_thunk=original_first_thunk,
            time_date_stamp=time_date_stamp,
            forwarder_chain=forwarder_chain,
            name_rva=name_rva,
            first_thunk=first_thunk,
            imports=imports
        ))

        ctx.reader.seek(current_pos)

    return descriptors

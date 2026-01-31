SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", 
    "CreateRemoteThread", "WinExec", "LoadLibraryA", "GetProcAddress",
    "NtWriteVirtualMemory", "LdrLoadDll", "ShellExecuteA", "CreateProcessA"
}

from typing import List, Dict, Any
from pecli.core.context import PEContext
from pecli.pe.imports import parse_imports
from pecli.analysis.entropy import calculate_entropy

def run_heuristics(ctx: PEContext) -> Dict[str, Any]:
    results = {
        "suspicious_sections": [],
        "suspicious_imports": [],
        "high_entropy_sections": [],
        "score": 0
    }

    # 1. Check sections
    for section in ctx.sections:
        # RWX characteristics: IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
        # Standard values: 0x20000000 | 0x40000000 | 0x80000000 = 0xE0000000
        if (section.characteristics & 0xE0000000) == 0xE0000000:
            results["suspicious_sections"].append(f"RWX section: {section.name}")
            results["score"] += 30

        # High entropy
        ctx.reader.seek(section.pointer_to_raw_data)
        data = ctx.reader.read(section.size_of_raw_data)
        entropy = calculate_entropy(data)
        if entropy > 7.2:
            results["high_entropy_sections"].append({"name": section.name, "entropy": entropy})
            results["score"] += 20

        # Unusual names
        if section.name.lower() in [".vmp", ".packed", ".themida", ".upx"]:
            results["suspicious_sections"].append(f"Known packer section name: {section.name}")
            results["score"] += 40

    # 2. Check imports
    imports = parse_imports(ctx)
    for descriptor in imports:
        for imp in descriptor.imports:
            if imp.name in SUSPICIOUS_APIS:
                results["suspicious_imports"].append(imp.name)
                results["score"] += 10

    # 3. Overall heuristics
    if not imports:
        results["suspicious_imports"].append("No imports found (common in packed malware)")
        results["score"] += 50

    return results

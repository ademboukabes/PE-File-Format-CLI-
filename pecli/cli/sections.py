import click
from rich.console import Console
from rich.table import Table
from pecli.core.analyzer import PEAnalyzer
from pecli.analysis.entropy import calculate_entropy

console = Console()

def display_sections(file_path: str, entropy: bool, suspicious: bool):
    analyzer = PEAnalyzer(file_path)
    report = analyzer.analyze()
    ctx = report["ctx"]

    table = Table(title="PE Sections")
    table.add_column("Name", style="bold white")
    table.add_column("VirtAddress", style="cyan")
    table.add_column("VirtSize", style="cyan")
    table.add_column("RawSize", style="magenta")
    table.add_column("Perms", style="green")
    
    if entropy:
        table.add_column("Entropy", style="yellow")

    for section in ctx.sections:
        # Determine permissions
        perms = ""
        if section.characteristics & 0x40000000: perms += "R"
        if section.characteristics & 0x80000000: perms += "W"
        if section.characteristics & 0x20000000: perms += "X"
        
        is_suspicious = False
        if "X" in perms and "W" in perms: is_suspicious = True
        
        if suspicious and not is_suspicious:
            continue

        row = [
            section.name,
            hex(section.virtual_address),
            hex(section.virtual_size),
            hex(section.size_of_raw_data),
            perms
        ]
        
        if entropy:
            ctx.reader.seek(section.pointer_to_raw_data)
            data = ctx.reader.read(section.size_of_raw_data)
            e = calculate_entropy(data)
            row.append(f"{e:.2f}")

        table.add_row(*row)

    console.print(table)

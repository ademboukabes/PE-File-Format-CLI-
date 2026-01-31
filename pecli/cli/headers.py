import click
from rich.console import Console
from rich.table import Table
from pecli.core.analyzer import PEAnalyzer

console = Console()

def display_headers(file_path: str, dos: bool, file: bool, optional: bool):
    analyzer = PEAnalyzer(file_path)
    report = analyzer.analyze()
    ctx = report["ctx"]

    if dos or (not file and not optional):
        table = Table(title="DOS Header")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Magic", ctx.dos_header.magic.decode())
        table.add_row("e_lfanew (Offset to PE)", hex(ctx.dos_header.e_lfanew))
        console.print(table)

    if file or (not dos and not optional):
        fh = ctx.nt_headers.file_header
        table = Table(title="File Header")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Machine", hex(fh.machine))
        table.add_row("Number of Sections", str(fh.number_of_sections))
        table.add_row("Timestamp", str(fh.timestamp))
        table.add_row("Characteristics", hex(fh.characteristics))
        console.print(table)

    if optional or (not dos and not file):
        oh = ctx.nt_headers.optional_header
        table = Table(title="Optional Header")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="magenta")
        table.add_row("Magic", hex(oh.magic))
        table.add_row("Address Of Entry Point", hex(oh.address_of_entry_point))
        table.add_row("Image Base", hex(oh.image_base))
        table.add_row("Section Alignment", hex(oh.section_alignment))
        table.add_row("File Alignment", hex(oh.file_alignment))
        table.add_row("Size of Image", hex(oh.size_of_image))
        table.add_row("Subsystem", hex(oh.subsystem))
        console.print(table)

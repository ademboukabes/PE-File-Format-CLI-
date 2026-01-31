import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from pecli.core.analyzer import PEAnalyzer

console = Console()

def display_info(file_path: str):
    analyzer = PEAnalyzer(file_path)
    report = analyzer.analyze()
    ctx = report["ctx"]
    
    table = Table(title="PE Global Information", show_header=False, box=None)
    table.add_row("Path", file_path)
    
    machine_map = {0x014c: "x86", 0x8664: "x64", 0x0200: "Intel Itanium", 0xaa64: "ARM64"}
    machine = ctx.nt_headers.file_header.machine
    table.add_row("Architecture", machine_map.get(machine, f"Unknown ({hex(machine)})"))
    
    magic_map = {0x10b: "PE32 (32-bit)", 0x20b: "PE32+ (64-bit)"}
    table.add_row("Format", magic_map.get(ctx.nt_headers.optional_header.magic, "Unknown"))
    
    table.add_row("Entry Point", hex(ctx.nt_headers.optional_header.address_of_entry_point))
    table.add_row("Sections", str(len(ctx.sections)))
    table.add_row("Entropy", f"{report['entropy']:.4f}")
    
    is_packed = report["heuristics"]["score"] > 50
    packing_status = "[bold red]YES[/bold red]" if is_packed else "[bold green]NO[/bold green]"
    table.add_row("Suspicion of Packing", packing_status)
    
    console.print(Panel(table, border_style="blue", title="[bold white]pecli info[/bold white]"))

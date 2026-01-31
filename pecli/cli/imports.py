import click
from rich.console import Console
from rich.table import Table
from pecli.core.analyzer import PEAnalyzer
from pecli.pe.imports import parse_imports
from pecli.analysis.heuristics import SUSPICIOUS_APIS

console = Console()

def display_imports(file_path: str, dll_only: bool, api_only: bool, suspicious: bool):
    analyzer = PEAnalyzer(file_path)
    report = analyzer.analyze()
    ctx = report["ctx"]
    imports = parse_imports(ctx)

    if not imports:
        console.print("[yellow]No imports found.[/yellow]")
        return

    for descriptor in imports:
        if api_only:
            # Just list APIs
            for imp in descriptor.imports:
                if suspicious and imp.name not in SUSPICIOUS_APIS:
                    continue
                console.print(f"- {imp.name}")
        else:
            table = Table(title=f"Imports from {descriptor.dll_name}")
            table.add_column("Hint", style="dim")
            table.add_column("Function", style="bold green")
            
            count = 0
            for imp in descriptor.imports:
                if suspicious and imp.name not in SUSPICIOUS_APIS:
                    continue
                table.add_row(hex(imp.hint), imp.name)
                count += 1
            
            if count > 0 and not dll_only:
                console.print(table)
            elif count > 0 and dll_only:
                console.print(f"[bold blue]{descriptor.dll_name}[/bold blue]")

import json
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from pecli.core.analyzer import PEAnalyzer

console = Console()

def display_scan(file_path: str, as_json: bool):
    analyzer = PEAnalyzer(file_path)
    report = analyzer.analyze()
    h = report["heuristics"]

    if as_json:
        # Prepare a clean JSON report
        output = {
            "file": file_path,
            "entropy": report["entropy"],
            "suspicion_score": h["score"],
            "suspicious_sections": h["suspicious_sections"],
            "suspicious_imports": h["suspicious_imports"],
            "high_entropy_sections": h["high_entropy_sections"]
        }
        print(json.dumps(output, indent=2))
        return

    # Visual Scan Report
    console.print(Panel(f"[bold white]Malware Scan Report: {file_path}[/bold white]", border_style="magenta"))

    # Score Panel
    score = h["score"]
    color = "green" if score < 30 else "yellow" if score < 70 else "red"
    console.print(f"Suspicion Score: [{color}]{score}/100[/{color}]")

    if h["suspicious_sections"]:
        table = Table(title="Suspicious Sections", border_style="red")
        table.add_column("Issue", style="bold red")
        for issue in h["suspicious_sections"]:
            table.add_row(issue)
        console.print(table)

    if h["high_entropy_sections"]:
        table = Table(title="High Entropy Sections (Potential Packing)", border_style="yellow")
        table.add_column("Section", style="bold")
        table.add_column("Entropy", style="yellow")
        for item in h["high_entropy_sections"]:
            table.add_row(item["name"], f"{item['entropy']:.2f}")
        console.print(table)

    if h["suspicious_imports"]:
        table = Table(title="Suspicious API Imports", border_style="red")
        table.add_column("API Name", style="bold red")
        for api in h["suspicious_imports"]:
            table.add_row(api)
        console.print(table)

    if score > 50:
        console.print("\n[bold red]🚩 VERDICT: POSSIBLY MALICIOUS OR PACKED[/bold red]")
    else:
        console.print("\n[bold green]✅ VERDICT: APPEARS LEGITIMATE[/bold green]")

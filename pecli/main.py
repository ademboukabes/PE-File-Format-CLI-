import click
from pecli.cli.info import display_info
from pecli.cli.headers import display_headers
from pecli.cli.sections import display_sections
from pecli.cli.imports import display_imports
from pecli.cli.scan import display_scan

@click.group()
def cli():
    """pecli - A powerful Portable Executable analysis tool."""
    pass

@cli.command()
@click.argument("file", type=click.Path(exists=True))
def info(file):
    """View global PE information."""
    display_info(file)

@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--dos", is_flag=True, help="Show DOS Header")
@click.option("--file", 'file_header', is_flag=True, help="Show File Header")
@click.option("--optional", is_flag=True, help="Show Optional Header")
def headers(file, dos, file_header, optional):
    """View PE headers."""
    display_headers(file, dos, file_header, optional)

@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--entropy", is_flag=True, help="Calculate and show section entropy")
@click.option("--suspicious", is_flag=True, help="Filter for suspicious sections")
def sections(file, entropy, suspicious):
    """Analyze PE sections."""
    display_sections(file, entropy, suspicious)

@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--dll-only", is_flag=True, help="Only show DLL names")
@click.option("--api-only", is_flag=True, help="Only show API names")
@click.option("--suspicious", is_flag=True, help="Highlight suspicious APIs")
def imports(file, dll_only, api_only, suspicious):
    """List imported DLLs and functions."""
    display_imports(file, dll_only, api_only, suspicious)

@cli.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--json", 'as_json', is_flag=True, help="Output results in JSON format")
def scan(file, as_json):
    """Perform an automated malware/packing scan."""
    display_scan(file, as_json)

def main():
    cli()

if __name__ == "__main__":
    main()

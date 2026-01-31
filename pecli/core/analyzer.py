from typing import Dict, Any
from pecli.core.context import PEContext
from pecli.analysis.entropy import calculate_entropy
from pecli.analysis.heuristics import run_heuristics
from pecli.pe.imports import parse_imports

class PEAnalyzer:
    def __init__(self, file_path: str):
        self.file_path = file_path
        with open(file_path, "rb") as f:
            self.data = f.read()
        self.ctx = PEContext(self.data)

    def analyze(self) -> Dict[str, Any]:
        self.ctx.parse()
        
        entropy = calculate_entropy(self.data)
        heuristics = run_heuristics(self.ctx)
        imports = parse_imports(self.ctx)

        return {
            "path": self.file_path,
            "ctx": self.ctx,
            "entropy": entropy,
            "heuristics": heuristics,
            "imports": imports
        }

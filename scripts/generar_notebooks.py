"""Genera y ejecuta los notebooks SEMMA a partir de sus fuentes (notebooks/fuentes/*.py, formato jupytext).

Uso: python scripts/generar_notebooks.py [01 02 ...]
"""

import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
NOTEBOOKS = BASE / "notebooks"


def main():
    filtros = sys.argv[1:]
    for fuente in sorted((NOTEBOOKS / "fuentes").glob("*.py")):
        if filtros and not any(fuente.stem.startswith(f) for f in filtros):
            continue
        destino = NOTEBOOKS / f"{fuente.stem}.ipynb"
        print(f"generando {destino.name} ...", flush=True)
        subprocess.run([sys.executable, "-m", "jupytext", "--to", "ipynb", "--output", str(destino), str(fuente)],
                       check=True, capture_output=True)
        subprocess.run([sys.executable, "-m", "jupyter", "nbconvert", "--to", "notebook", "--execute", "--inplace",
                        "--ExecutePreprocessor.timeout=3600", "--ExecutePreprocessor.kernel_name=python3", str(destino)],
                       check=True, cwd=NOTEBOOKS)


if __name__ == "__main__":
    main()

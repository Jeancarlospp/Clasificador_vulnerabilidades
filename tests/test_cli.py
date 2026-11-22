"""Pruebas de integración: análisis de un proyecto completo con el modelo entrenado y CLI."""

import json
import os
import subprocess
import sys

import pytest

from vulnminer.analizador import analizar_proyecto, cargar_modelo
from vulnminer.cli import main

CAMPOS = {"id", "microservicio", "archivo", "linea", "descripcion", "evidencia", "owasp_top10", "owasp_api", "cwe",
          "confianza", "severidad", "justificacion_severidad", "recomendacion", "estado"}


@pytest.fixture(scope="module")
def resultado(proyecto, ruta_modelo):
    return analizar_proyecto(proyecto, cargar_modelo(ruta_modelo))


def test_resumen(resultado):
    r = resultado["resumen"]
    assert r["microservicios"] == 3
    assert r["archivos_analizados"] >= 9 and r["unidades_analizadas"] >= r["archivos_analizados"]
    assert r["hallazgos"] == len(resultado["hallazgos"])


def test_cada_hallazgo_tiene_la_informacion_minima(resultado):
    assert resultado["hallazgos"], "se esperaban hallazgos en el proyecto de prueba"
    ids = [h["id"] for h in resultado["hallazgos"]]
    assert len(set(ids)) == len(ids)
    for h in resultado["hallazgos"]:
        assert CAMPOS <= set(h)
        assert h["linea"] >= 1 and h["severidad"] in {"Baja", "Media", "Alta", "Crítica"}
        assert 0 <= h["confianza"] <= 1 and h["recomendacion"] and h["descripcion"]
        assert h["evidencia"]["fragmento"] and any(f["resaltada"] for f in h["evidencia"]["fragmento"])
        if not h["owasp_top10"] and not h["owasp_api"]:
            assert h["estado"].startswith("Pendiente")


def test_detecta_la_inyeccion_sql_del_proyecto(resultado):
    sql = [h for h in resultado["hallazgos"] if h["archivo"].endswith("ProductController.java")]
    assert sql and sql[0]["microservicio"] == "products"
    assert any(c["codigo"] == "A05:2025" for c in sql[0]["owasp_top10"])
    assert sql[0]["linea"] in (6, 7, 8)


def test_categorias_no_evaluadas_declaradas(resultado):
    estados = {c: d["estado"] for c, d in resultado["categorias"].items()}
    assert len(estados) == 20
    assert estados["API6:2023"] == "no evaluada"


def test_cli_scan_genera_json_y_html(proyecto, ruta_modelo, tmp_path, capsys):
    salida = tmp_path / "reportes"
    cwd = os.getcwd()
    os.chdir(proyecto)
    try:
        codigo = main(["scan", ".", "--standards", "owasp2025,api2023", "--format", "json,html", "--output", str(salida), "-q"])
    finally:
        os.chdir(cwd)
    assert codigo == 0
    consola = capsys.readouterr().out
    assert "VULNMINER - SECURITY SCAN" in consola and "REPORTES GENERADOS" in consola
    datos = json.loads((salida / "analisis.json").read_text())
    assert datos["resumen"]["hallazgos"] == len(datos["hallazgos"]) and "por_categoria" in datos["resumen"]
    html = (salida / "analisis.html").read_text()
    assert html.startswith("<!doctype html>") and "Hallazgos por microservicio y categoría" in html
    assert "<script>" in html and html.count('class="hallazgo"') == len(datos["hallazgos"])


def test_cli_filtra_por_estandar(proyecto, ruta_modelo, tmp_path, capsys):
    assert main(["scan", str(proyecto), "--standards", "api2023", "--format", "json", "--output", str(tmp_path), "-q"]) == 0
    datos = json.loads((tmp_path / "analisis.json").read_text())
    assert all(not h["owasp_top10"] for h in datos["hallazgos"])
    assert set(datos["categorias"]) == {f"API{i}:2023" for i in range(1, 11)}


def test_cli_errores_de_uso(tmp_path, capsys):
    assert main(["scan", str(tmp_path / "no-existe")]) == 2
    assert main(["scan", ".", "--format", "pdf"]) == 2
    assert main(["scan", ".", "--standards", "owasp2017"]) == 2
    assert "no válido" in capsys.readouterr().err


def test_cli_fragmento(ruta_modelo, capsys):
    assert main(["fragmento", "--codigo", "import os\ndef f(request):\n    os.system('ping ' + request.args['h'])",
                 "--lenguaje", "python"]) == 0
    assert "VULNERABLE" in capsys.readouterr().out


def test_comando_instalado():
    r = subprocess.run([sys.executable, "-m", "vulnminer.cli", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and "vulnminer" in r.stdout

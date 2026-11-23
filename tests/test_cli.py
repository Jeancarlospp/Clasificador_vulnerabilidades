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


def test_linea_reportada_es_la_operacion_peligrosa(ruta_modelo, tmp_path):
    from vulnminer.analizador import analizar_unidades, cargar_modelo
    from vulnminer.segmentacion import segmentar

    codigo = ('@router.post("/draft/restore")\nasync def restore_draft(request: Request):\n'
              '    data = base64.b64decode(request.cookies.get("draft", ""))\n    draft = pickle.loads(data)\n    return {"ok": True}\n')
    d = analizar_unidades(cargar_modelo(ruta_modelo), segmentar("r.py", codigo))
    assert d and d[0]["linea"] == 4


# ------------------------------------------------------------------ casos límite
def test_directorio_sin_archivos_soportados(ruta_modelo, tmp_path, capsys):
    (tmp_path / "vacio").mkdir()
    (tmp_path / "vacio" / "notas.txt").write_text("nada que analizar")
    assert main(["scan", str(tmp_path / "vacio"), "--output", str(tmp_path / "r"), "-q", "--format", "json"]) == 0
    assert "no se encontraron archivos soportados" in capsys.readouterr().out
    assert json.loads((tmp_path / "r" / "analisis.json").read_text())["resumen"]["hallazgos"] == 0


def test_archivos_binarios_grandes_e_ilegibles_se_omiten(ruta_modelo, tmp_path, capsys):
    svc = tmp_path / "p" / "svc"
    svc.mkdir(parents=True)
    (svc / "package.json").write_text('{"name": "svc", "dependencies": {"express": "4"}}')
    (svc / "imagen.js").write_bytes(bytes(range(256)) * 80)
    (svc / "enorme.js").write_text("function f(){ return 1 }\n" * 60000)
    (svc / "ok.js").write_text("function f(req, res) { db.query('SELECT * FROM t WHERE id=' + req.params.id) }\n")
    salida = tmp_path / "r"
    assert main(["scan", str(tmp_path / "p"), "--output", str(salida), "-q", "--format", "json"]) == 0
    datos = json.loads((salida / "analisis.json").read_text())
    assert datos["resumen"]["archivos_omitidos"] == {"contenido binario": 1, "mayor a 1 MB": 1}
    assert {h["archivo"] for h in datos["hallazgos"]} == {"svc/ok.js"}
    assert "Archivos omitidos" in capsys.readouterr().out


def test_umbral_fuera_de_rango_y_modelo_inexistente(tmp_path, capsys):
    assert main(["scan", str(tmp_path), "--threshold", "3"]) == 2
    assert main(["scan", str(tmp_path), "--modelo", str(tmp_path / "no.joblib"), "-q"]) == 2
    err = capsys.readouterr().err
    assert "umbral" in err and "No se encontró el modelo" in err


def test_combinacion_solo_en_codigo_de_servidor(ruta_modelo):
    import numpy as np
    from vulnminer.analizador import cargar_modelo
    from vulnminer.segmentacion import segmentar

    m = cargar_modelo(ruta_modelo)
    servidor = segmentar("s.py", "def f(request):\n    os.system('ping ' + request.args['h'])\n")
    config = segmentar("Dockerfile", "FROM python:latest\nUSER root\n")
    navegador = segmentar("v.tsx", "export function f(id) { return fetch('/api/' + id) }\n")
    for u in navegador:
        u.meta["frontend"] = True
    unidades = servidor + config + navegador
    p = m.probabilidad(unidades)
    vulnerable, confianza, q = m.decision(unidades, p)
    assert len(vulnerable) == len(unidades) and np.all(confianza >= p - 1e-12)
    if m.combinador is not None:
        assert not np.isnan(q[0]) and np.isnan(q[len(servidor)]) and np.isnan(q[-1])

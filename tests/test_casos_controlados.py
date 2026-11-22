"""Pruebas de los casos controlados: cada caso debe etiquetar exactamente una unidad."""

import json
from collections import Counter
from pathlib import Path

import pytest

from vulnminer.segmentacion import segmentar

RAIZ = Path(__file__).resolve().parents[1] / "datos" / "casos_controlados"
MANIFIESTO = RAIZ / "manifiesto.json"

pytestmark = pytest.mark.skipif(not MANIFIESTO.exists(), reason="ejecute scripts/generar_casos_controlados.py")


def casos():
    return json.loads(MANIFIESTO.read_text())


def test_cada_caso_corresponde_a_una_unidad():
    errores = []
    for c in casos():
        unidades = segmentar(c["archivo"], (RAIZ / c["archivo"]).read_text())
        marcadas = [u for u in unidades if c["linea"] in u.lineas]
        if len(marcadas) != 1:
            errores.append((c["archivo"], c["linea"], len(marcadas)))
    assert not errores, errores[:10]


def test_pares_balanceados_por_familia():
    conteo = Counter((c["familia"], c["vulnerable"]) for c in casos())
    for familia in {c["familia"] for c in casos()}:
        assert conteo[(familia, 1)] == conteo[(familia, 0)], familia


def test_vulnerables_tienen_categoria_y_corregidos_no():
    for c in casos():
        if c["vulnerable"]:
            assert c["cwe"] and c["owasp2025"], c["archivo"]
        else:
            assert not c["cwe"] and not c["api2023"], c["archivo"]


def test_cubre_categorias_api_sin_datos_publicos():
    api = {a for c in casos() for a in c["api2023"]}
    assert {"API1:2023", "API3:2023", "API4:2023", "API5:2023", "API9:2023", "API10:2023"} <= api

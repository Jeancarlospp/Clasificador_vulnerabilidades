"""Pruebas de la estimación de severidad y del estado de verificación."""

from vulnminer.segmentacion import Unidad
from vulnminer.severidad import estado, estimar


def u(archivo="src/app.py"):
    return Unidad(archivo, "python", "codigo", "f", [1], "x")


def test_severidad_base_del_cwe():
    nivel, just = estimar("CWE-89", ["A05:2025"], u(), set())
    assert nivel == "Crítica" and "CWE-89" in just


def test_entrada_hacia_operacion_peligrosa_eleva_severidad():
    base, _ = estimar("CWE-22", ["A01:2025"], u(), set())
    alta, just = estimar("CWE-22", ["A01:2025"], u(), {"x_entrada_archivo_sin_normalizar"})
    assert base == "Alta" and alta == "Crítica" and "petición" in just


def test_archivo_de_pruebas_reduce_severidad():
    nivel, just = estimar("CWE-798", ["A07:2025"], u("tests/test_login.py"), set())
    assert nivel == "Media" and "pruebas" in just


def test_sin_cwe_usa_la_categoria():
    assert estimar(None, ["API4:2023"], u(), set())[0] == "Media"
    assert estimar(None, [], u(), set())[0] == "Media"


def test_la_severidad_no_depende_de_la_confianza():
    # la función no recibe la probabilidad del modelo: misma entrada -> misma severidad
    assert estimar("CWE-639", ["API1:2023"], u(), set()) == estimar("CWE-639", ["API1:2023"], u(), set())


def test_estados():
    assert estado([], set(), False).startswith("Pendiente de revisión")
    assert "manual" in estado(["API1:2023"], set(), True)
    assert "evidencia estática" in estado(["A05:2025"], {"x_entrada_sql"}, True)
    assert estado(["A04:2025"], set(), True) == "Potencial - requiere verificación"

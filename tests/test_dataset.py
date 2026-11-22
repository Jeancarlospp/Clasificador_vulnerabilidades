"""Validación del dataset etiquetado (requisitos de la fase Sample)."""

import re
from pathlib import Path

import pandas as pd
import pytest

from vulnminer.catalogo import API2023, OWASP2025
from vulnminer.lexico import limpiar_codigo

RUTA = Path(__file__).resolve().parents[1] / "datos" / "dataset.csv"
pytestmark = pytest.mark.skipif(not RUTA.exists(), reason="ejecute scripts/construir_dataset.py")


@pytest.fixture(scope="module")
def df():
    return pd.read_csv(RUTA, keep_default_na=False)


def test_minimos_del_enunciado(df):
    assert len(df) >= 500
    assert (df.vulnerable == 0).sum() >= 100


def test_columnas_y_diccionario(df):
    dic = pd.read_csv(RUTA.with_name("diccionario_datos.csv"))
    assert set(dic["columna"]) == set(df.columns)


def test_identificadores_unicos(df):
    assert df["id"].is_unique


def test_proporciones_de_particion(df):
    p = df["particion"].value_counts(normalize=True)
    assert set(p.index) == {"entrenamiento", "validacion", "prueba"}
    assert 0.62 <= p["entrenamiento"] <= 0.78
    assert 0.10 <= p["validacion"] <= 0.20 and 0.10 <= p["prueba"] <= 0.20


def test_sin_fuga_de_grupos_entre_particiones(df):
    particiones_por_grupo = df.groupby("proyecto")["particion"].nunique()
    assert (particiones_por_grupo == 1).all(), particiones_por_grupo[particiones_por_grupo > 1].head()


def test_sin_codigo_repetido_entre_particiones(df):
    norm = df["codigo"].map(lambda c: re.sub(r"\s+", " ", limpiar_codigo(c)).strip())
    assert norm.is_unique


def test_etiquetas_consistentes(df):
    vul = df[df.vulnerable == 1]
    seg = df[df.vulnerable == 0]
    assert (vul["owasp2025"] != "").all()
    assert (seg[["cwe", "owasp2025", "api2023"]] == "").all().all()
    validas_t10, validas_api = set(OWASP2025), set(API2023)
    for v in vul["owasp2025"]:
        assert set(v.split(";")) <= validas_t10
    for v in vul["api2023"]:
        assert v == "" or set(v.split(";")) <= validas_api
    for v in vul["cwe"]:
        assert all(re.fullmatch(r"CWE-\d+", c) for c in v.split(";"))


def test_lenguajes_del_alcance(df):
    assert set(df["lenguaje"]) <= {"java", "python", "javascript", "typescript", "config"}
    assert {"java", "python", "javascript", "typescript"} <= set(df["lenguaje"])


def test_cobertura_de_categorias(df):
    vul = df[df.vulnerable == 1]
    t10 = set(vul["owasp2025"].str.split(";").explode())
    api = set(vul["api2023"].str.split(";").explode()) - {""}
    assert len(t10) >= 5 and len(api) >= 4
    for particion in ("entrenamiento", "prueba"):
        sub = df[(df.particion == particion) & (df.vulnerable == 1)]
        assert len(set(sub["owasp2025"].str.split(";").explode())) >= 5, particion


def test_trazabilidad_de_cada_registro(df):
    assert (df["fuente"] != "").all() and (df["origen_etiqueta"] != "").all()
    assert (df["archivo"] != "").all() and (df["linea_inicio"] > 0).all()

"""Pruebas de la calibración del umbral con la política de dos niveles."""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import desarrollo  # noqa: E402


def test_sin_categoria_exige_umbral_estricto():
    p = np.array([0.3, 0.3, 0.6])
    cat = np.array([True, False, False])
    marcadas = desarrollo._marcadas(p, cat, umbral=0.25, umbral_sin_categoria=0.5)
    assert marcadas.tolist() == [True, False, True]


def test_umbral_operativo_respeta_presupuesto_de_falsas_alarmas():
    rng = np.random.default_rng(0)
    p_neg = rng.uniform(0, 1, 1000)
    u = desarrollo.umbral_operativo(p_neg, maximo=0.05)
    assert (p_neg >= u).mean() <= 0.05 and (p_neg >= u - 0.02).mean() > 0.05


def test_metricas_con_politica():
    m = desarrollo.metricas(np.array([0.9, 0.3]), np.array([0.1, 0.2, 0.3]), umbral=0.25,
                            cat_pos=np.array([True, True]), cat_neg=np.array([False, False, False]), umbral_sin_categoria=0.5)
    assert m["sensibilidad"] == 1.0 and m["falsas_alarmas"] == 0.0

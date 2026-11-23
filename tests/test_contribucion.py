"""Funciones auxiliares del estudio de contribución del modelo (scripts/contribucion.py)."""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from contribucion import puntaje_reglas, sensibilidad_a_falsas_alarmas  # noqa: E402
from vulnminer.segmentacion import segmentar  # noqa: E402


def test_sensibilidad_con_falsas_alarmas_acotadas():
    neg = np.linspace(0, 1, 100)
    pos = np.array([0.99, 0.97, 0.5, 0.1])
    sens, fa = sensibilidad_a_falsas_alarmas(pos, neg, 0.05)
    assert fa <= 0.05 and sens == 0.5


def test_puntaje_de_reglas_cuenta_operaciones_peligrosas():
    vulnerable = segmentar("a.py", "def f(request):\n    os.system('ping ' + request.args['h'])\n")
    segura = segmentar("b.py", "def g(a, b):\n    return a + b\n")
    p = puntaje_reglas(vulnerable + segura)
    assert p[0] >= 1 and p[1] == 0

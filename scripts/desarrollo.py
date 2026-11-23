"""Conjunto de DESARROLLO a nivel de proyecto (evaluacion/desarrollo.json).

La partición de validación proviene de las mismas fuentes que el entrenamiento (pruebas de reglas,
proyectos benignos), por lo que no refleja bien cómo luce una vulnerabilidad dentro de una
aplicación real. El conjunto de desarrollo está formado por:

- unidades vulnerables documentadas en aplicaciones vulnerables reales (laboratorios de PyGoat y NodeGoat);
- todas las unidades de proyectos benignos reservados (no usados en el entrenamiento).

Se usa para (1) elegir la variante de la representación y (2) fijar el umbral de operación. No
participa en el entrenamiento ni en la evaluación final (evaluacion/verdad_terreno.json).
"""

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from vulnminer.descubrimiento import descubrir, es_generado  # noqa: E402
from vulnminer.segmentacion import segmentar  # noqa: E402

FALSAS_ALARMAS_MAX = 0.05
PROYECTOS_BENIGNOS_DESARROLLO = {"fastapi-realworld", "spring-boot-realworld", "nestjs-realworld"}


def cargar(ruta=BASE / "evaluacion" / "desarrollo.json"):
    """Devuelve (positivas, negativas): listas de unidades."""
    spec = json.loads(Path(ruta).read_text(encoding="utf-8"))
    positivas, negativas, vistas = [], [], set()
    for nombre, p in spec["proyectos"].items():
        raiz = BASE / p["ruta"]
        if not raiz.exists():
            raise FileNotFoundError(f"Falta el proyecto de desarrollo {nombre}: ejecute scripts/descargar_fuentes.py")
        if p["tipo"] == "vulnerable":
            for v in p["vulnerabilidades"]:
                texto = (raiz / v["archivo"]).read_text(encoding="utf-8", errors="ignore")
                for u in segmentar(v["archivo"], texto):
                    clave = (nombre, u.archivo, u.linea_inicio, u.linea_fin)
                    if v["linea"] in u.lineas and clave not in vistas:
                        vistas.add(clave)
                        positivas.append(u)
        else:
            servicios, _ = descubrir(raiz)
            for s in servicios:
                for rel in s.archivos:
                    texto = (raiz / rel).read_text(encoding="utf-8", errors="ignore")
                    if not es_generado(rel, texto):
                        negativas.extend(segmentar(rel, texto))
    return positivas, negativas


def umbral_operativo(p_neg, maximo=FALSAS_ALARMAS_MAX):
    """Menor umbral con tasa de falsas alarmas <= maximo en los proyectos limpios de desarrollo."""
    return float(np.quantile(p_neg, 1 - maximo)) if len(p_neg) else 0.5


def metricas(p_pos, p_neg, umbral=None):
    y = np.r_[np.ones(len(p_pos)), np.zeros(len(p_neg))]
    p = np.r_[p_pos, p_neg]
    u = umbral_operativo(p_neg) if umbral is None else umbral
    return {"positivas": int(len(p_pos)), "negativas": int(len(p_neg)), "ap": float(average_precision_score(y, p)),
            "auc": float(roc_auc_score(y, p)), "umbral": round(u, 4),
            "sensibilidad": float((np.asarray(p_pos) >= u).mean()),
            "falsas_alarmas": float((np.asarray(p_neg) >= u).mean())}

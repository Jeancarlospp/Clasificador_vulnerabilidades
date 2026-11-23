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

from vulnminer.descubrimiento import descubrir, es_generado, marcar_frontend  # noqa: E402
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
                        negativas.extend(marcar_frontend(segmentar(rel, texto), s, rel))
    return positivas, negativas


def _marcadas(p, con_categoria, umbral, umbral_sin_categoria):
    p = np.asarray(p)
    if con_categoria is None:
        return p >= umbral
    return (p >= umbral) & (np.asarray(con_categoria) | (p >= max(umbral, umbral_sin_categoria)))


def umbral_operativo(p_neg, maximo=FALSAS_ALARMAS_MAX, cat_neg=None, umbral_sin_categoria=1.0):
    """Menor umbral con tasa de falsas alarmas <= maximo en los proyectos limpios de desarrollo
    (aplicando la política de dos niveles si se indican las categorías)."""
    if not len(p_neg):
        return 0.5
    for u in np.round(np.arange(0.05, 0.951, 0.01), 2):
        if _marcadas(p_neg, cat_neg, u, umbral_sin_categoria).mean() <= maximo:
            return float(u)
    return 0.95


def metricas(p_pos, p_neg, umbral=None, cat_pos=None, cat_neg=None, umbral_sin_categoria=1.0):
    y = np.r_[np.ones(len(p_pos)), np.zeros(len(p_neg))]
    p = np.r_[p_pos, p_neg]
    u = umbral_operativo(p_neg, cat_neg=cat_neg, umbral_sin_categoria=umbral_sin_categoria) if umbral is None else umbral
    return {"positivas": int(len(p_pos)), "negativas": int(len(p_neg)), "ap": float(average_precision_score(y, p)),
            "auc": float(roc_auc_score(y, p)), "umbral": round(u, 4),
            "sensibilidad": float(_marcadas(p_pos, cat_pos, u, umbral_sin_categoria).mean()),
            "falsas_alarmas": float(_marcadas(p_neg, cat_neg, u, umbral_sin_categoria).mean())}

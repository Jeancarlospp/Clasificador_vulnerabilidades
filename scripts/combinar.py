"""Etapa de combinación (iteración ASSESS -> MODIFY/MODEL).

La ablación (scripts/contribucion.py) mostró un cambio de distribución: en los datos de entrenamiento
(pruebas de reglas, Benchmark, casos controlados) la versión vulnerable y la segura de un caso tienen casi
las mismas operaciones peligrosas, por lo que el modelo aprende a no dar peso a la *cantidad* de evidencia
estática. En las aplicaciones reales, en cambio, las funciones vulnerables suelen acumular varias
operaciones peligrosas a la vez (entrada + consulta + respuesta sin filtrar...).

Esta etapa ajusta, con el conjunto de DESARROLLO (aplicaciones reales; no participa en el entrenamiento
ni en la evaluación final), una regresión logística de dos variables:

    logit(probabilidad del modelo)  y  número de indicadores de operación peligrosa activos.

Solo se aplica al código de servidor: el conjunto de desarrollo no tiene vulnerabilidades de configuración
ni de código de navegador, así que para Dockerfile, compose, YAML, manifiestos y frontend (React, Angular,
Vue, archivos .jsx/.tsx) se conserva la decisión del modelo base.

Decisión en código: vulnerable si p >= u_base o q >= u_comb. Los umbrales se eligen con predicciones fuera
de pliegue (validación cruzada de 5 pliegues) en el conjunto de desarrollo: para cada u_base se busca el
menor u_comb con <= 5 % de falsas alarmas; se elige la mayor sensibilidad y, dentro de una tolerancia de
una vulnerabilidad, el u_base más bajo (la opción que más respeta al modelo base).

Salidas: actualiza vulnminer/modelos/vulnminer.joblib, resultados/seleccion_combinacion.csv y la
sección "combinacion" de resultados/metricas.json.

Uso: python scripts/combinar.py
"""

import json
import sys
import warnings
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from vulnminer.analizador import RUTA_MODELO, cargar_modelo  # noqa: E402
from vulnminer.modelo import a_unidades, entradas_combinador  # noqa: E402

import desarrollo  # noqa: E402
from entrenar import metricas_binarias  # noqa: E402

warnings.filterwarnings("ignore")
RESULTADOS = BASE / "resultados"
UMBRALES_BASE = np.round(np.arange(0.35, 0.801, 0.05), 2)
CANDIDATOS = np.round(np.arange(0.05, 0.991, 0.01), 2)


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


def decidir(p, q, codigo, u_base, u_comb, u_conf):
    return np.where(codigo, (p >= u_base) | (q >= u_comb), p >= u_conf)


def main():
    modelo = cargar_modelo()
    modelo.combinador = modelo.umbral_base_codigo = modelo.umbral_combinado = None
    pos, neg = desarrollo.cargar()
    unidades = pos + neg
    y = np.r_[np.ones(len(pos)), np.zeros(len(neg))]
    codigo = np.array([u.subtipo == "codigo" and not (u.meta or {}).get("frontend") for u in unidades])
    p = modelo.probabilidad(unidades)
    X = entradas_combinador(p, unidades)
    log(f"desarrollo: {len(pos)} vulnerables ({int(codigo[y == 1].sum())} de código), {len(neg)} limpias "
        f"({int(codigo[y == 0].sum())} de código)")

    combinador = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000)
    q = np.zeros(len(y))
    q[codigo] = cross_val_predict(combinador, X[codigo], y[codigo], method="predict_proba",
                                  cv=StratifiedKFold(5, shuffle=True, random_state=42))[:, 1]

    filas = []
    for u_base in UMBRALES_BASE:
        u_comb = next((float(c) for c in CANDIDATOS
                       if decidir(p, q, codigo, u_base, c, modelo.umbral)[y == 0].mean() <= desarrollo.FALSAS_ALARMAS_MAX), None)
        if u_comb is None:
            continue
        d = decidir(p, q, codigo, u_base, u_comb, modelo.umbral)
        filas.append({"umbral_base_codigo": float(u_base), "umbral_combinado": u_comb,
                      "sensibilidad": float(d[y == 1].mean()), "falsas_alarmas": float(d[y == 0].mean())})
    base = {"umbral_base_codigo": modelo.umbral, "umbral_combinado": None,
            "sensibilidad": float((p[y == 1] >= modelo.umbral).mean()), "falsas_alarmas": float((p[y == 0] >= modelo.umbral).mean())}
    tabla = pd.DataFrame(filas)
    tolerancia = 1 / len(pos)
    elegible = tabla[tabla.sensibilidad >= tabla.sensibilidad.max() - tolerancia - 1e-9]
    elegida = elegible.sort_values("umbral_base_codigo").iloc[0]
    tabla["elegida"] = tabla.umbral_base_codigo == elegida.umbral_base_codigo
    tabla.to_csv(RESULTADOS / "seleccion_combinacion.csv", index=False)
    for _, f in tabla.iterrows():
        log(f"  p >= {f.umbral_base_codigo:.2f} o q >= {f.umbral_combinado:.2f}: sensibilidad={f.sensibilidad:.2f} "
            f"falsas alarmas={f.falsas_alarmas:.3f}{'  <== elegida' if f.elegida else ''}")
    log(f"modelo base solo (umbral {modelo.umbral}): sensibilidad={base['sensibilidad']:.2f} falsas alarmas={base['falsas_alarmas']:.3f}")

    combinador.fit(X[codigo], y[codigo])
    modelo.combinador = combinador
    modelo.umbral_base_codigo = float(elegida.umbral_base_codigo)
    modelo.umbral_combinado = float(elegida.umbral_combinado)
    coef = dict(zip(["logit_probabilidad", "evidencia_estatica"], combinador.coef_[0].round(3).tolist()))
    log(f"combinador: coeficientes={coef} intercepto={combinador.intercept_[0]:.3f}")

    # Partición de prueba con la decisión completa (modelo base + combinación)
    df = pd.read_csv(BASE / "datos" / "dataset.csv", keep_default_na=False)
    te = df[df.particion == "prueba"].reset_index(drop=True)
    u_te = a_unidades(te)
    p_te = modelo.probabilidad(u_te)
    d_te, conf_te, _ = modelo.decision(u_te, p_te)
    m_final = metricas_binarias(te.vulnerable.values, conf_te, 0.5)
    m_final.update({k: v for k, v in metricas_binarias(te.vulnerable.values, d_te.astype(float), 0.5).items()
                    if k not in ("roc_auc", "ap")})
    log(f"PRUEBA con la decisión completa: P={m_final['precision']:.3f} R={m_final['recall']:.3f} F1={m_final['f1']:.3f} "
        f"FPR={m_final['tasa_falsos_positivos']:.3f}")

    metr = json.loads((RESULTADOS / "metricas.json").read_text())
    metr["combinacion"] = {
        "descripcion": "regresión logística sobre [logit(p), evidencia estática] ajustada con el conjunto de desarrollo; solo código",
        "coeficientes": coef, "intercepto": float(combinador.intercept_[0]),
        "umbral_base_codigo": modelo.umbral_base_codigo, "umbral_combinado": modelo.umbral_combinado,
        "desarrollo_fuera_de_pliegue": {"sensibilidad": float(elegida.sensibilidad), "falsas_alarmas": float(elegida.falsas_alarmas)},
        "desarrollo_modelo_base": base, "prueba": m_final}
    (RESULTADOS / "metricas.json").write_text(json.dumps(metr, indent=2, ensure_ascii=False, default=float))
    modelo.metadatos["combinacion"] = {k: metr["combinacion"][k] for k in ("coeficientes", "umbral_base_codigo", "umbral_combinado")}
    modelo.metadatos["detector_prueba_final"] = {k: m_final[k] for k in ("precision", "recall", "f1")}
    modelo.guardar(RUTA_MODELO)
    log(f"modelo guardado en {RUTA_MODELO.relative_to(BASE)} ({RUTA_MODELO.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()

"""Fases MODIFY, MODEL y ASSESS (parte cuantitativa): entrenamiento, comparación y evaluación.

1. Representación: TF-IDF de tokens + TF-IDF de caracteres + características de seguridad,
   ajustada SOLO con la partición de entrenamiento.
2. Comparación del detector (vulnerable / no vulnerable): regresión logística, SVM lineal,
   Random Forest y Gradient Boosting, cada uno con su rejilla de hiperparámetros y dos pesos
   para el bloque de características de seguridad. Selección por precisión promedio (AP) en
   validación; se informa también F1, precisión, sensibilidad y AUC.
3. Comparación del clasificador multietiqueta de categorías OWASP (mismos algoritmos).
   Selección por F1 macro en validación.
4. Clasificador de CWE (regresión logística multinomial).
5. Umbrales: el del detector y uno por categoría, elegidos en validación (máximo F1).
6. Modelo final: se reentrena con entrenamiento + validación y se evalúa UNA vez en prueba.

Salidas:
  vulnminer/modelos/vulnminer.joblib     modelo serializado (pipeline completo)
  resultados/comparacion_detector.csv    comparación de algoritmos (validación y prueba)
  resultados/comparacion_categorias.csv
  resultados/metricas.json               métricas finales en prueba
  resultados/predicciones_prueba.csv     predicciones para el análisis de errores

Uso: python scripts/entrenar.py [--rapido]
"""

import argparse
import json
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.base import clone
from sklearn.decomposition import TruncatedSVD
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix, f1_score,
                             multilabel_confusion_matrix, precision_recall_fscore_support, precision_score,
                             recall_score, roc_auc_score)
from sklearn.multiclass import OneVsRestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MaxAbsScaler

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from vulnminer import __version__  # noqa: E402
from vulnminer.catalogo import API2023, OWASP2025  # noqa: E402
from vulnminer.modelo import (CATEGORIAS, NOMBRES_ALGORITMO, REJILLAS, ModeloVulnminer, _caracteristicas,  # noqa: E402
                              a_unidades, crear_clasificador, probabilidades, representacion)

import desarrollo  # noqa: E402

warnings.filterwarnings("ignore")
RESULTADOS = BASE / "resultados"
MIN_EJEMPLOS_CATEGORIA = 15
MIN_EJEMPLOS_CWE = 10
PESOS_SEGURIDAD = (1.0, 3.0)
VARIANTES = {"log + estilo": (False, True), "binario + estilo": (True, True),
             "log sin estilo": (False, False), "binario sin estilo": (True, False)}
TOLERANCIA = 0.01
TOLERANCIA_CAT = 0.02


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


# ---------------------------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------------------------
def bloques(R, unidades):
    """Matrices de los tres bloques de la representación (sin ponderar)."""
    return [t.transform(unidades) for _, t in R.transformer_list]


def combinar(bl, peso):
    return sparse.hstack([bl[0], bl[1], bl[2] * peso]).tocsr()


def multihot(serie_owasp, serie_api, categorias):
    filas = []
    for a, b in zip(serie_owasp, serie_api):
        etiquetas = set(filter(None, a.split(";"))) | set(filter(None, b.split(";")))
        filas.append([int(c in etiquetas) for c in categorias])
    return np.array(filas)


def metricas_binarias(y, p, umbral):
    yp = (p >= umbral).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yp, labels=[0, 1]).ravel()
    return {"precision": precision_score(y, yp, zero_division=0), "recall": recall_score(y, yp, zero_division=0),
            "f1": f1_score(y, yp, zero_division=0), "accuracy": accuracy_score(y, yp),
            "roc_auc": roc_auc_score(y, p), "ap": average_precision_score(y, p),
            "tasa_falsos_positivos": fp / max(fp + tn, 1), "TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn)}


def mejor_umbral(y, p, desde=0.2, hasta=0.85):
    candidatos = np.round(np.arange(desde, hasta + 1e-9, 0.01), 2)
    f1s = [f1_score(y, (p >= u).astype(int), zero_division=0) for u in candidatos]
    return float(candidatos[int(np.argmax(f1s))]), float(max(f1s))


def ajustar_multietiqueta(algoritmo, params, X, Y):
    """Clasificador multietiqueta (one-vs-rest). Para Gradient Boosting la reducción SVD se
    calcula una sola vez y no por etiqueta."""
    if algoritmo == "gradient_boosting":
        svd = TruncatedSVD(n_components=params.get("componentes", 200), random_state=42)
        hgb = clone(crear_clasificador(algoritmo, **params).named_steps["hgb"])
        modelo = Pipeline([("svd", svd), ("ovr", OneVsRestClassifier(hgb, n_jobs=-1))])
    else:
        modelo = OneVsRestClassifier(crear_clasificador(algoritmo, **params), n_jobs=-1 if algoritmo != "svm_lineal" else 4)
    return modelo.fit(X, Y)


def umbrales_por_categoria(Y, P, categorias, minimo=5):
    umbrales = {}
    for k, c in enumerate(categorias):
        if Y[:, k].sum() >= minimo:
            umbrales[c] = mejor_umbral(Y[:, k], P[:, k], 0.15, 0.8)[0]
        else:
            umbrales[c] = 0.5
    return umbrales


def aplicar_umbrales(P, categorias, umbrales):
    return np.column_stack([(P[:, k] >= umbrales[c]).astype(int) for k, c in enumerate(categorias)])


# ---------------------------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rapido", action="store_true", help="rejillas reducidas (pruebas)")
    args = ap.parse_args()
    RESULTADOS.mkdir(exist_ok=True)

    df = pd.read_csv(BASE / "datos" / "dataset.csv", keep_default_na=False)
    tr, va, te = (df[df.particion == p].reset_index(drop=True) for p in ("entrenamiento", "validacion", "prueba"))
    log(f"entrenamiento={len(tr)} validacion={len(va)} prueba={len(te)}")
    u_tr, u_va, u_te = a_unidades(tr), a_unidades(va), a_unidades(te)

    # ------------------------------------------------------------------ representación
    t0 = time.time()
    R = representacion().fit(u_tr)
    b_tr, b_va, b_te = bloques(R, u_tr), bloques(R, u_va), bloques(R, u_te)
    dims = {n: b.shape[1] for (n, _), b in zip(R.transformer_list, b_tr)}
    log(f"representación ajustada en {time.time() - t0:.0f}s: {dims}")

    # ------------------------------------------------------------------ variante de la representación (desarrollo)
    # Las variantes solo cambian el bloque de características de seguridad: indicadores como presencia
    # (binario) o log(1 + conteo), y con o sin métricas de estilo del código. Se elige por la precisión
    # promedio en el conjunto de DESARROLLO (aplicaciones reales), no en validación.
    dev_pos, dev_neg = desarrollo.cargar()
    u_dev = dev_pos + dev_neg
    y_dev = np.r_[np.ones(len(dev_pos)), np.zeros(len(dev_neg))]
    b_dev = bloques(R, u_dev)
    log(f"desarrollo: {len(dev_pos)} unidades vulnerables documentadas, {len(dev_neg)} unidades de proyectos limpios")
    filas_var, seguridad = [], {}
    for nombre, (binario, estilo) in VARIANTES.items():
        esc = MaxAbsScaler().fit(_caracteristicas(u_tr, binario, estilo))
        seg = {k: esc.transform(_caracteristicas(u, binario, estilo)) for k, u in (("tr", u_tr), ("va", u_va), ("te", u_te), ("dev", u_dev))}
        seguridad[nombre] = seg
        for peso in PESOS_SEGURIDAD:
            Xtr_v = sparse.hstack([b_tr[0], b_tr[1], seg["tr"] * peso]).tocsr()
            m = crear_clasificador("regresion_logistica", C=2.0).fit(Xtr_v, tr.vulnerable)
            p_va = m.predict_proba(sparse.hstack([b_va[0], b_va[1], seg["va"] * peso]).tocsr())[:, 1]
            p_dev = m.predict_proba(sparse.hstack([b_dev[0], b_dev[1], seg["dev"] * peso]).tocsr())[:, 1]
            md = desarrollo.metricas(p_dev[y_dev == 1], p_dev[y_dev == 0])
            filas_var.append({"variante": nombre, "binario": binario, "estilo": estilo, "peso_seguridad": peso,
                              "val_ap": average_precision_score(va.vulnerable, p_va), "dev_ap": md["ap"], "dev_auc": md["auc"],
                              "dev_sensibilidad_5pct": md["sensibilidad"]})
            log(f"variante {nombre:20s} peso={peso} AP val={filas_var[-1]['val_ap']:.3f} | desarrollo AP={md['ap']:.3f} "
                f"AUC={md['auc']:.3f} sensibilidad con 5% de falsas alarmas={md['sensibilidad']:.2f}")
    comp_var = pd.DataFrame(filas_var).sort_values(["dev_ap", "val_ap"], ascending=False)
    comp_var.to_csv(RESULTADOS / "seleccion_variante.csv", index=False)
    variante = comp_var.iloc[0]["variante"]
    binario, estilo = VARIANTES[variante]
    log(f"==> variante seleccionada: {variante} (AP desarrollo={comp_var.iloc[0]['dev_ap']:.3f})")
    b_tr, b_va, b_te = ([b[0], b[1], seguridad[variante][k]] for b, k in ((b_tr, "tr"), (b_va, "va"), (b_te, "te")))

    # ------------------------------------------------------------------ detector
    filas = []
    rejillas = {a: (r[:1] if args.rapido else r) for a, r in REJILLAS.items()}
    pesos = PESOS_SEGURIDAD[:1] if args.rapido else PESOS_SEGURIDAD
    for peso in pesos:
        X_tr, X_va, X_te = combinar(b_tr, peso), combinar(b_va, peso), combinar(b_te, peso)
        for alg, rejilla in rejillas.items():
            for params in rejilla:
                t0 = time.time()
                m = crear_clasificador(alg, **params).fit(X_tr, tr.vulnerable)
                seg = time.time() - t0
                p_va = m.predict_proba(X_va)[:, 1]
                p_te = m.predict_proba(X_te)[:, 1]
                umbral, _ = mejor_umbral(va.vulnerable, p_va)
                fila = {"algoritmo": alg, "nombre": NOMBRES_ALGORITMO[alg], "peso_seguridad": peso,
                        "hiperparametros": json.dumps(params), "segundos": round(seg, 1), "umbral_validacion": umbral}
                fila.update({f"val_{k}": v for k, v in metricas_binarias(va.vulnerable, p_va, 0.5).items()})
                fila["val_f1_umbral"] = metricas_binarias(va.vulnerable, p_va, umbral)["f1"]
                fila.update({f"prueba_{k}": v for k, v in metricas_binarias(te.vulnerable, p_te, umbral).items()})
                filas.append(fila)
                log(f"detector {alg:20s} peso={peso} {params} AP={fila['val_ap']:.3f} F1={fila['val_f1']:.3f} "
                    f"F1u={fila['val_f1_umbral']:.3f} ({seg:.0f}s)")
    comp = pd.DataFrame(filas)
    # Regla de parsimonia: dentro de cada algoritmo, entre las configuraciones cuya AP está a menos de
    # TOLERANCIA de la mejor, se elige la más regularizada (menor C) o la más simple. Reduce el riesgo de
    # que variables raras reciban pesos excesivos y generaliza mejor a proyectos nuevos.
    elegidas = []
    for alg, sub in comp.groupby("algoritmo"):
        cerca = sub[sub["val_ap"] >= sub["val_ap"].max() - TOLERANCIA]
        clave = cerca["hiperparametros"].map(lambda h: json.loads(h).get("C", 0))
        elegidas.append(cerca.assign(_c=clave).sort_values(["_c", "val_ap"], ascending=[True, False]).index[0])
    comp["mejor_del_algoritmo"] = comp.index.isin(elegidas)
    comp.to_csv(RESULTADOS / "comparacion_detector.csv", index=False)
    mejor = comp[comp.mejor_del_algoritmo].sort_values("val_ap", ascending=False).iloc[0]
    alg_det, params_det, peso = mejor["algoritmo"], json.loads(mejor["hiperparametros"]), float(mejor["peso_seguridad"])
    log(f"==> detector seleccionado: {alg_det} {params_det} peso={peso} (AP validación={mejor['val_ap']:.3f})")

    X_tr, X_va, X_te = combinar(b_tr, peso), combinar(b_va, peso), combinar(b_te, peso)

    # ------------------------------------------------------------------ categorías
    vt, vv = tr.vulnerable == 1, va.vulnerable == 1
    Y_all_tr = multihot(tr.owasp2025, tr.api2023, CATEGORIAS)
    conteo = dict(zip(CATEGORIAS, Y_all_tr[vt.values].sum(axis=0).tolist()))
    categorias = [c for c in CATEGORIAS if conteo[c] >= MIN_EJEMPLOS_CATEGORIA]
    no_evaluadas = {c: f"datos insuficientes para entrenar ({conteo[c]} ejemplos; mínimo {MIN_EJEMPLOS_CATEGORIA})"
                    for c in CATEGORIAS if c not in categorias}
    log(f"categorías con clasificador: {len(categorias)} | no evaluadas: {list(no_evaluadas)}")
    Ytr = multihot(tr.owasp2025, tr.api2023, categorias)[vt.values]
    Yva = multihot(va.owasp2025, va.api2023, categorias)[vv.values]
    filas = []
    for _, fila in comp[comp.mejor_del_algoritmo].iterrows():
        alg, params = fila["algoritmo"], json.loads(fila["hiperparametros"])
        t0 = time.time()
        m = ajustar_multietiqueta(alg, params, X_tr[vt.values], Ytr)
        P = probabilidades(m, X_va[vv.values])
        umb = umbrales_por_categoria(Yva, P, categorias)
        pred = aplicar_umbrales(P, categorias, umb)
        presentes = Yva.sum(axis=0) > 0
        filas.append({"algoritmo": alg, "nombre": NOMBRES_ALGORITMO[alg], "hiperparametros": json.dumps(params),
                      "segundos": round(time.time() - t0, 1),
                      "val_f1_micro": f1_score(Yva, pred, average="micro", zero_division=0),
                      "val_f1_macro": f1_score(Yva[:, presentes], pred[:, presentes], average="macro", zero_division=0),
                      "val_f1_macro_umbral05": f1_score(Yva[:, presentes], (P >= 0.5)[:, presentes].astype(int), average="macro", zero_division=0),
                      "val_exactitud_subconjunto": float((pred == Yva).all(axis=1).mean())})
        log(f"categorías {alg:20s} F1 micro={filas[-1]['val_f1_micro']:.3f} macro={filas[-1]['val_f1_macro']:.3f} ({filas[-1]['segundos']:.0f}s)")
    comp_cat = pd.DataFrame(filas)
    comp_cat.to_csv(RESULTADOS / "comparacion_categorias.csv", index=False)
    # Parsimonia: si la diferencia de F1 macro con el mejor es menor que TOLERANCIA_CAT, se prefiere el
    # algoritmo más simple (lineal), que además es interpretable y produce un modelo serializado liviano.
    simplicidad = {"regresion_logistica": 0, "svm_lineal": 1, "random_forest": 2, "gradient_boosting": 3}
    cerca = comp_cat[comp_cat["val_f1_macro"] >= comp_cat["val_f1_macro"].max() - TOLERANCIA_CAT]
    mejor_cat = cerca.assign(_s=cerca["algoritmo"].map(simplicidad)).sort_values("_s").iloc[0]
    alg_cat, params_cat = mejor_cat["algoritmo"], json.loads(mejor_cat["hiperparametros"])
    log(f"==> categorizador seleccionado: {alg_cat} (F1 macro validación={mejor_cat['val_f1_macro']:.3f})")

    # umbrales con los modelos entrenados solo con entrenamiento
    det = crear_clasificador(alg_det, **params_det).fit(X_tr, tr.vulnerable)
    umbral, _ = mejor_umbral(va.vulnerable, det.predict_proba(X_va)[:, 1])
    cat = ajustar_multietiqueta(alg_cat, params_cat, X_tr[vt.values], Ytr)
    umbrales_cat = umbrales_por_categoria(Yva, probabilidades(cat, X_va[vv.values]), categorias)
    log(f"umbral detector={umbral} | umbrales por categoría={umbrales_cat}")

    # ------------------------------------------------------------------ CWE
    def cwe_principal(s):
        return s.split(";")[0] if s else ""
    cwe_tr = tr.cwe.map(cwe_principal)
    frecuentes = cwe_tr[vt].value_counts()
    frecuentes = list(frecuentes[frecuentes >= MIN_EJEMPLOS_CWE].index)
    mascara_cwe = vt & cwe_tr.isin(frecuentes)
    cls_cwe = LogisticRegression(C=4.0, max_iter=5000, class_weight="balanced").fit(X_tr[mascara_cwe.values], cwe_tr[mascara_cwe])
    cwe_va = va.cwe.map(cwe_principal)
    m_va = (vv & cwe_va.isin(frecuentes)).values
    acc_cwe_va = accuracy_score(cwe_va[m_va], cls_cwe.predict(X_va[m_va]))
    log(f"CWE: {len(frecuentes)} clases, exactitud validación={acc_cwe_va:.3f}")

    # ------------------------------------------------------------------ modelo final (entrenamiento + validación)
    log("reentrenando con entrenamiento + validación ...")
    trva = pd.concat([tr, va], ignore_index=True)
    u_trva = a_unidades(trva)
    R_final = representacion(peso_caracteristicas=peso, binario=binario, estilo=estilo).fit(u_trva)
    X_final = R_final.transform(u_trva)
    vtv = (trva.vulnerable == 1).values
    det_final = crear_clasificador(alg_det, **params_det).fit(X_final, trva.vulnerable)
    Y_final = multihot(trva.owasp2025, trva.api2023, categorias)[vtv]
    cat_final = ajustar_multietiqueta(alg_cat, params_cat, X_final[vtv], Y_final)
    cwe_trva = trva.cwe.map(cwe_principal)
    m_cwe = vtv & cwe_trva.isin(frecuentes).values
    cwe_final = LogisticRegression(C=4.0, max_iter=5000, class_weight="balanced").fit(X_final[m_cwe], cwe_trva[m_cwe])

    modelo = ModeloVulnminer(representacion=R_final, detector=det_final, categorizador=cat_final, clasificador_cwe=cwe_final,
                             categorias=categorias, umbral=umbral, umbrales_categoria=umbrales_cat,
                             algoritmo_detector=alg_det, algoritmo_categorias=alg_cat, no_evaluadas=no_evaluadas)

    # Umbral de operación: menor umbral con <= 5 % de falsas alarmas en los proyectos limpios de
    # desarrollo. El umbral de validación (máximo F1) se conserva como referencia.
    umbral_validacion = umbral
    modelo.umbral_sin_categoria = umbral_validacion
    X_dev = modelo.transformar(u_dev)
    p_dev = modelo.probabilidad(X=X_dev)
    Pc_dev = modelo.probabilidad_categorias(X=X_dev)
    con_cat = (Pc_dev >= np.array([umbrales_cat[c] for c in categorias])).any(axis=1)
    kw = dict(cat_pos=con_cat[y_dev == 1], cat_neg=con_cat[y_dev == 0], umbral_sin_categoria=umbral_validacion)
    md_val = desarrollo.metricas(p_dev[y_dev == 1], p_dev[y_dev == 0], umbral_validacion, **kw)
    md_dev = desarrollo.metricas(p_dev[y_dev == 1], p_dev[y_dev == 0], **kw)
    umbral = min(round(md_dev["umbral"], 2), umbral_validacion)
    modelo.umbral = umbral
    log(f"umbral de validación={umbral_validacion} (desarrollo: sensibilidad {md_val['sensibilidad']:.2f}, falsas alarmas "
        f"{md_val['falsas_alarmas']:.3f}) | umbral operativo={umbral} (sensibilidad {md_dev['sensibilidad']:.2f}, "
        f"falsas alarmas {md_dev['falsas_alarmas']:.3f})")

    # ------------------------------------------------------------------ evaluación en prueba
    log("evaluando en la partición de prueba ...")
    X_te_f = R_final.transform(u_te)
    p_te = modelo.probabilidad(X=X_te_f)
    det_metricas = metricas_binarias(te.vulnerable, p_te, umbral)
    det_metricas["umbral"] = umbral
    det_metricas_val = metricas_binarias(te.vulnerable, p_te, umbral_validacion)
    det_metricas_val["umbral"] = umbral_validacion
    Pc = modelo.probabilidad_categorias(X=X_te_f)
    pred_cat = aplicar_umbrales(Pc, categorias, umbrales_cat)
    Yte = multihot(te.owasp2025, te.api2023, categorias)
    vte = (te.vulnerable == 1).values
    # (a) categorías dado que la unidad es vulnerable
    presentes = Yte[vte].sum(axis=0) > 0
    p_, r_, f_, s_ = precision_recall_fscore_support(Yte[vte], pred_cat[vte], zero_division=0)
    # (b) extremo a extremo: detectada como vulnerable Y con la categoría correcta
    detectada = (p_te >= umbral).astype(int)[:, None]
    p2, r2, f2, s2 = precision_recall_fscore_support(Yte, pred_cat * detectada, zero_division=0)
    mcm = multilabel_confusion_matrix(Yte, pred_cat * detectada)
    por_categoria = {}
    for k, c in enumerate(categorias):
        por_categoria[c] = {"soporte_prueba": int(s2[k]), "precision": float(p2[k]), "recall": float(r2[k]), "f1": float(f2[k]),
                            "precision_dado_vulnerable": float(p_[k]), "recall_dado_vulnerable": float(r_[k]),
                            "f1_dado_vulnerable": float(f_[k]), "ejemplos_entrenamiento": int(conteo[c]),
                            "matriz_confusion": mcm[k].tolist()}
    sin_categoria = int(((pred_cat.sum(axis=1) == 0) & (p_te >= umbral)).sum())
    cat_metricas = {"f1_micro": f1_score(Yte[vte], pred_cat[vte], average="micro", zero_division=0),
                    "f1_macro": f1_score(Yte[vte][:, presentes], pred_cat[vte][:, presentes], average="macro", zero_division=0),
                    "f1_micro_extremo_a_extremo": f1_score(Yte, pred_cat * detectada, average="micro", zero_division=0),
                    "f1_macro_extremo_a_extremo": f1_score(Yte[:, presentes], (pred_cat * detectada)[:, presentes], average="macro", zero_division=0),
                    "hallazgos_pendientes_de_revision": sin_categoria}
    cwe_te = te.cwe.map(cwe_principal)
    m_te = (vte & cwe_te.isin(frecuentes).values)
    acc_cwe = accuracy_score(cwe_te[m_te], modelo.clasificador_cwe.predict(X_te_f[m_te]))

    # por fuente y por subtipo
    def por_grupo(col):
        out = {}
        for g, idx in te.groupby(col).groups.items():
            y = te.vulnerable.loc[idx].values
            pr = p_te[idx]
            yp = (pr >= umbral).astype(int)
            out[g] = {"n": int(len(idx)), "vulnerables": int(y.sum()), "accuracy": float((yp == y).mean()),
                      "precision": float(precision_score(y, yp, zero_division=0)), "recall": float(recall_score(y, yp, zero_division=0)),
                      "f1": float(f1_score(y, yp, zero_division=0))}
        return out

    metricas = {
        "fecha": datetime.now().isoformat(timespec="seconds"), "version": __version__,
        "particiones": {"entrenamiento": len(tr), "validacion": len(va), "prueba": len(te)},
        "representacion": {**dims, "peso_seguridad": peso, "variante": variante, "binario": bool(binario), "estilo": bool(estilo)},
        "desarrollo": {"umbral_validacion": umbral_validacion, "con_umbral_validacion": md_val, "con_umbral_operativo": md_dev},
        "detector": {"algoritmo": alg_det, "hiperparametros": params_det, "prueba": det_metricas,
                     "prueba_umbral_validacion": det_metricas_val,
                     "por_fuente": por_grupo("fuente"), "por_lenguaje": por_grupo("lenguaje"), "por_subtipo": por_grupo("subtipo")},
        "categorias": {"algoritmo": alg_cat, "hiperparametros": params_cat, "evaluadas": categorias, "no_evaluadas": no_evaluadas,
                       "umbrales": umbrales_cat, "prueba": cat_metricas, "por_categoria": por_categoria},
        "cwe": {"clases": frecuentes, "exactitud_validacion": acc_cwe_va, "exactitud_prueba": acc_cwe},
    }
    modelo.metadatos = {"version": __version__, "fecha": metricas["fecha"], "particiones": metricas["particiones"],
                        "detector_prueba": {k: det_metricas[k] for k in ("precision", "recall", "f1", "roc_auc")},
                        "categorias_prueba": cat_metricas, "por_categoria": {c: {k: v for k, v in d.items() if k != "matriz_confusion"}
                                                                             for c, d in por_categoria.items()}}
    destino = BASE / "vulnminer" / "modelos" / "vulnminer.joblib"
    destino.parent.mkdir(exist_ok=True)
    modelo.guardar(destino)
    (RESULTADOS / "metricas.json").write_text(json.dumps(metricas, indent=2, ensure_ascii=False, default=float))

    pred = te[["id", "fuente", "proyecto", "archivo", "lenguaje", "subtipo", "unidad", "vulnerable", "cwe", "owasp2025", "api2023"]].copy()
    pred["probabilidad"] = np.round(p_te, 4)
    pred["prediccion"] = (p_te >= umbral).astype(int)
    pred["categorias_predichas"] = [";".join(c for k, c in enumerate(categorias) if pred_cat[i, k]) for i in range(len(te))]
    pred["cwe_predicho"] = modelo.clasificador_cwe.predict(X_te_f)
    pred.to_csv(RESULTADOS / "predicciones_prueba.csv", index=False)

    log(f"PRUEBA detector: P={det_metricas['precision']:.3f} R={det_metricas['recall']:.3f} F1={det_metricas['f1']:.3f} "
        f"AUC={det_metricas['roc_auc']:.3f} FPR={det_metricas['tasa_falsos_positivos']:.3f}")
    log(f"PRUEBA categorías: F1 micro={cat_metricas['f1_micro']:.3f} macro={cat_metricas['f1_macro']:.3f} | "
        f"extremo a extremo micro={cat_metricas['f1_micro_extremo_a_extremo']:.3f} | CWE acc={acc_cwe:.3f}")
    for c in categorias:
        d = por_categoria[c]
        log(f"   {c:11s} soporte={d['soporte_prueba']:4d} P={d['precision']:.2f} R={d['recall']:.2f} F1={d['f1']:.2f} "
            f"(dado vulnerable F1={d['f1_dado_vulnerable']:.2f})")
    log(f"modelo guardado en {destino.relative_to(BASE)} ({destino.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()

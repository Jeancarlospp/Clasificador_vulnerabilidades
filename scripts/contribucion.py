"""Contribución del modelo de clasificación (fase ASSESS).

Responde a la pregunta: ¿el modelo aporta algo frente a las reglas o frente a una herramienta existente?

1. Ablación del detector. Con el mismo algoritmo del modelo final (SVM lineal calibrada, C=1) y el mismo
   protocolo (umbral de máximo F1 en validación, reentrenamiento con entrenamiento + validación) se comparan:
     a) Reglas solas: sin aprendizaje; una unidad es vulnerable si activa al menos k indicadores de operación
        peligrosa o patrones combinados (k elegido en validación y, aparte, k calibrado en desarrollo como el
        umbral del modelo).
     b) Solo indicadores de análisis estático (149 variables) con el clasificador.
     c) Solo representación textual (TF-IDF de tokens y de caracteres) con el clasificador.
     d) Modelo completo (TF-IDF + indicadores), el modelo base de la herramienta.
     e) Modelo completo + etapa de combinación (scripts/combinar.py): la decisión final de la herramienta.
   También se incluye (b') indicadores con Random Forest, para descartar que la diferencia se deba a usar
   un clasificador lineal sobre variables que podrían requerir uno no lineal.
   Cada variante se mide en la partición de prueba y, a nivel de unidad, en los proyectos externos:
   las funciones con vulnerabilidades documentadas frente a todas las unidades de los proyectos limpios.

2. Comparación con Semgrep (análisis estático por reglas, con las reglas comunitarias del repositorio
   semgrep-rules descargado en fuentes/) sobre los mismos proyectos y con el mismo criterio de acierto
   que la evaluación de la herramienta: un hallazgo dentro de la función documentada.

Salidas: resultados/contribucion_modelo.json, resultados/ablacion.csv, resultados/comparacion_semgrep.csv

Uso: python scripts/contribucion.py [--semgrep RUTA_EJECUTABLE]
"""

import argparse
import json
import shutil
import subprocess
import sys
import time
import warnings
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.preprocessing import MaxAbsScaler

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts"))

from vulnminer import caracteristicas as C  # noqa: E402
from vulnminer.descubrimiento import descubrir, es_generado, marcar_frontend  # noqa: E402
from vulnminer.modelo import _caracteristicas, a_unidades, crear_clasificador, representacion  # noqa: E402
from vulnminer.segmentacion import segmentar  # noqa: E402

import entrenar as E  # noqa: E402
from evaluar import unidad_de_linea  # noqa: E402

warnings.filterwarnings("ignore")
RESULTADOS = BASE / "resultados"
LENGUAJES_SEMGREP = ("python", "java", "javascript", "typescript", "dockerfile", "yaml", "generic", "json")
FALSAS_ALARMAS_REFERENCIA = 0.05


def log(msg):
    print(f"[{datetime.now():%H:%M:%S}] {msg}", flush=True)


# ---------------------------------------------------------------------------------------------
# Unidades de los proyectos externos
# ---------------------------------------------------------------------------------------------
def unidades_externas(verdad):
    """positivas: unidad que contiene cada vulnerabilidad documentada; negativas: todas las unidades
    de los proyectos de referencia (limpios); demo: unidades del proyecto de demostración."""
    pos, neg, demo = [], [], []
    for nombre, spec in verdad["proyectos"].items():
        raiz = BASE / spec["ruta"]
        if spec["tipo"] == "referencia":
            servicios, _ = descubrir(raiz)
            for s in servicios:
                for rel in s.archivos:
                    texto = (raiz / rel).read_text(encoding="utf-8", errors="ignore")
                    if not es_generado(rel, texto):
                        neg.extend((nombre, u) for u in marcar_frontend(segmentar(rel, texto), s, rel))
            continue
        destino = pos if spec["tipo"] == "vulnerable" else demo
        for v in spec["vulnerabilidades"]:
            u = unidad_de_linea(raiz, v["archivo"], v["linea"])
            if u is not None:
                destino.append((nombre, v["id"], u))
    return pos, neg, demo


def puntaje_reglas(unidades):
    """Cantidad de indicadores de operación peligrosa y patrones combinados activos (sin aprendizaje)."""
    return np.array([C.puntaje_evidencia(u) for u in unidades])


def sensibilidad_a_falsas_alarmas(p_pos, p_neg, maximo=FALSAS_ALARMAS_REFERENCIA):
    """Sensibilidad con el menor umbral que deja como máximo `maximo` de falsas alarmas en los proyectos limpios."""
    umbral = np.quantile(p_neg, 1 - maximo, method="higher")
    umbral = np.nextafter(umbral, np.inf)
    return float((p_pos >= umbral).mean()), float((p_neg >= umbral).mean())


def medir_externo(p_pos, p_neg, p_demo, umbral):
    y = np.r_[np.ones(len(p_pos)), np.zeros(len(p_neg))]
    s = np.r_[p_pos, p_neg]
    sens5, fa5 = sensibilidad_a_falsas_alarmas(p_pos, p_neg)
    return {"detectadas": int((p_pos >= umbral).sum()), "documentadas": int(len(p_pos)),
            "sensibilidad": float((p_pos >= umbral).mean()), "falsas_alarmas": float((p_neg >= umbral).mean()),
            "unidades_limpias_marcadas": int((p_neg >= umbral).sum()), "unidades_limpias": int(len(p_neg)),
            "auc": float(roc_auc_score(y, s)), "ap": float(average_precision_score(y, s)),
            "sensibilidad_con_5pct_falsas_alarmas": sens5,
            "demo_detectadas": int((p_demo >= umbral).sum()), "demo_sembradas": int(len(p_demo))}


# ---------------------------------------------------------------------------------------------
# Ablación
# ---------------------------------------------------------------------------------------------
def ablacion(tr, va, te, externos):
    pos, neg, demo = externos
    u_tr, u_va, u_te = a_unidades(tr), a_unidades(va), a_unidades(te)
    u_pos, u_neg, u_demo = [x[-1] for x in pos], [x[-1] for x in neg], [x[-1] for x in demo]
    trva = pd.concat([tr, va], ignore_index=True)
    u_trva = a_unidades(trva)
    metr = json.loads((RESULTADOS / "metricas.json").read_text())
    alg, params = metr["detector"]["algoritmo"], metr["detector"]["hiperparametros"]
    binario, estilo = metr["representacion"]["binario"], metr["representacion"]["estilo"]
    filas = []

    # ---- (a) reglas solas
    t0 = time.time()
    s_va, s_te = puntaje_reglas(u_va), puntaje_reglas(u_te)
    candidatos = [k for k in range(1, 6)]
    f1s = [E.metricas_binarias(va.vulnerable, s_va, k)["f1"] for k in candidatos]
    k = candidatos[int(np.argmax(f1s))]
    filas.append({"variante": "Reglas solas, k elegido en validación", "clave": "reglas", "umbral": k,
                  "variables": int(sum(1 for n in C.nombres_caracteristicas()
                                       if (n in C.FAMILIA and C.FAMILIA[n] not in C.FAMILIAS_CONTEXTO) or n.startswith("x_"))),
                  **{f"prueba_{m}": v for m, v in E.metricas_binarias(te.vulnerable, s_te, k).items()},
                  **{f"ext_{m}": v for m, v in medir_externo(puntaje_reglas(u_pos), puntaje_reglas(u_neg),
                                                              puntaje_reglas(u_demo), k).items()},
                  "segundos": round(time.time() - t0, 1)})
    log(f"reglas solas: k={k} F1 prueba={filas[-1]['prueba_f1']:.3f} externo {filas[-1]['ext_detectadas']}/"
        f"{filas[-1]['ext_documentadas']} falsas alarmas={filas[-1]['ext_falsas_alarmas']:.3f}")

    # ---- (a') reglas solas con k calibrado como el modelo: menor k con <= 5 % de falsas alarmas en los
    #          proyectos limpios del conjunto de desarrollo (aplicaciones reales)
    import desarrollo
    dev_pos, dev_neg = desarrollo.cargar()
    s_dev_neg = puntaje_reglas(dev_neg)
    k_dev = next(k for k in range(1, 20) if (s_dev_neg >= k).mean() <= desarrollo.FALSAS_ALARMAS_MAX)
    filas.append({**filas[0], "variante": "Reglas solas, k calibrado en desarrollo", "clave": "reglas_desarrollo", "umbral": k_dev,
                  **{f"prueba_{m}": v for m, v in E.metricas_binarias(te.vulnerable, s_te, k_dev).items()},
                  **{f"ext_{m}": v for m, v in medir_externo(puntaje_reglas(u_pos), puntaje_reglas(u_neg),
                                                              puntaje_reglas(u_demo), k_dev).items()}})
    log(f"reglas (desarrollo): k={k_dev} F1 prueba={filas[-1]['prueba_f1']:.3f} externo {filas[-1]['ext_detectadas']}/"
        f"{filas[-1]['ext_documentadas']} falsas alarmas={filas[-1]['ext_falsas_alarmas']:.3f}")

    # ---- representaciones aprendidas
    R = representacion(binario=binario, estilo=estilo).fit(u_tr)
    R_f = representacion(binario=binario, estilo=estilo).fit(u_trva)

    def matrices(Rep, unidades, columnas):
        bl = [t.transform(unidades) for _, t in Rep.transformer_list]
        return sparse.hstack([bl[i] for i in columnas]).tocsr()

    variantes = [("Solo indicadores de análisis estático", "indicadores", [2], alg, params),
                 ("Solo indicadores con Random Forest", "indicadores_rf", [2], "random_forest_denso", {}),
                 ("Solo texto (TF-IDF de tokens y caracteres)", "tfidf", [0, 1], alg, params),
                 ("Modelo completo (TF-IDF + indicadores)", "completo", [0, 1, 2], alg, params)]
    for nombre, clave, columnas, algoritmo, prm in variantes:
        t0 = time.time()

        def nuevo():
            if algoritmo == "random_forest_denso":
                return RandomForestClassifier(n_estimators=400, min_samples_leaf=2, class_weight="balanced_subsample",
                                              n_jobs=-1, random_state=42)
            return crear_clasificador(algoritmo, **prm)

        m = nuevo().fit(matrices(R, u_tr, columnas), tr.vulnerable)
        umbral, _ = E.mejor_umbral(va.vulnerable, m.predict_proba(matrices(R, u_va, columnas))[:, 1])
        X_f = matrices(R_f, u_trva, columnas)
        m = nuevo().fit(X_f, trva.vulnerable)
        prob = {k: m.predict_proba(matrices(R_f, u, columnas))[:, 1]
                for k, u in (("te", u_te), ("pos", u_pos), ("neg", u_neg), ("demo", u_demo))}
        filas.append({"variante": nombre, "clave": clave, "umbral": umbral, "variables": int(X_f.shape[1]),
                      **{f"prueba_{k}": v for k, v in E.metricas_binarias(te.vulnerable, prob["te"], umbral).items()},
                      **{f"ext_{k}": v for k, v in medir_externo(prob["pos"], prob["neg"], prob["demo"], umbral).items()},
                      "segundos": round(time.time() - t0, 1)})
        f = filas[-1]
        log(f"{clave:15s} umbral={umbral:.2f} prueba F1={f['prueba_f1']:.3f} AUC={f['prueba_roc_auc']:.3f} | externo "
            f"{f['ext_detectadas']}/{f['ext_documentadas']} falsas alarmas={f['ext_falsas_alarmas']:.3f} "
            f"AUC={f['ext_auc']:.3f} sens@5%={f['ext_sensibilidad_con_5pct_falsas_alarmas']:.2f} ({f['segundos']:.0f}s)")
    # ---- (e) herramienta final: modelo completo + etapa de combinación (scripts/combinar.py)
    from vulnminer.analizador import cargar_modelo
    t0 = time.time()
    modelo = cargar_modelo()

    def decidir(unidades):
        d, conf, _ = modelo.decision(unidades, modelo.probabilidad(unidades))
        return d.astype(float), conf

    d_te, c_te = decidir(u_te)
    (d_pos, c_pos), (d_neg, c_neg), (d_demo, _) = decidir(u_pos), decidir(u_neg), decidir(u_demo)
    prueba = E.metricas_binarias(te.vulnerable, d_te, 0.5)
    prueba.update({"roc_auc": roc_auc_score(te.vulnerable, c_te), "ap": average_precision_score(te.vulnerable, c_te)})
    externo = medir_externo(d_pos, d_neg, d_demo, 0.5)
    y_ext = np.r_[np.ones(len(c_pos)), np.zeros(len(c_neg))]
    sens5, _ = sensibilidad_a_falsas_alarmas(c_pos, c_neg)
    externo.update({"auc": float(roc_auc_score(y_ext, np.r_[c_pos, c_neg])),
                    "ap": float(average_precision_score(y_ext, np.r_[c_pos, c_neg])),
                    "sensibilidad_con_5pct_falsas_alarmas": sens5})
    filas.append({"variante": "Modelo completo + combinación (herramienta)", "clave": "herramienta",
                  "umbral": f"{modelo.umbral_base_codigo}/{modelo.umbral_combinado}", "variables": filas[-1]["variables"] + 1,
                  **{f"prueba_{k}": v for k, v in prueba.items()}, **{f"ext_{k}": v for k, v in externo.items()},
                  "segundos": round(time.time() - t0, 1)})
    f = filas[-1]
    log(f"herramienta     prueba F1={f['prueba_f1']:.3f} AUC={f['prueba_roc_auc']:.3f} | externo {f['ext_detectadas']}/"
        f"{f['ext_documentadas']} falsas alarmas={f['ext_falsas_alarmas']:.3f} AUC={f['ext_auc']:.3f} "
        f"sens@5%={f['ext_sensibilidad_con_5pct_falsas_alarmas']:.2f}")
    return pd.DataFrame(filas)


# ---------------------------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------------------------
def ejecutar_semgrep(semgrep, raiz):
    reglas = [a for l in LENGUAJES_SEMGREP for a in ("--config", str(BASE / "fuentes" / "semgrep-rules" / l))]
    t0 = time.time()
    r = subprocess.run([semgrep, "scan", "--metrics=off", "--disable-version-check", "--json", "-q", *reglas, "."],
                       cwd=raiz, capture_output=True, text=True)
    datos = json.loads(r.stdout or "{}")
    return [(x["path"], x["start"]["line"], x["end"]["line"], x["check_id"].split(".")[-1], x["extra"]["severity"])
            for x in datos.get("results", [])], round(time.time() - t0, 1)


def comparar_semgrep(semgrep, verdad):
    externa = json.loads((RESULTADOS / "evaluacion_externa.json").read_text())
    filas, detalle = [], []
    for nombre, spec in verdad["proyectos"].items():
        raiz = BASE / spec["ruta"]
        hallazgos, seg = ejecutar_semgrep(semgrep, raiz)
        vm = externa["proyectos"].get(nombre, {})
        fila = {"proyecto": nombre, "tipo": spec["tipo"], "semgrep_hallazgos": len(hallazgos), "semgrep_segundos": seg,
                "vulnminer_hallazgos": vm.get("hallazgos"), "vulnminer_segundos": vm.get("duracion_segundos")}
        if spec["tipo"] == "referencia":
            # unidades de análisis (las mismas que usa vulnminer) que contienen al menos un hallazgo de Semgrep
            servicios, _ = descubrir(raiz)
            total, marcadas = 0, 0
            por_archivo = {}
            for p, l1, l2, *_ in hallazgos:
                por_archivo.setdefault(p, []).append((l1, l2))
            for s in servicios:
                for rel in s.archivos:
                    texto = (raiz / rel).read_text(encoding="utf-8", errors="ignore")
                    if es_generado(rel, texto):
                        continue
                    for u in segmentar(rel, texto):
                        total += 1
                        marcadas += any(not (l2 < u.linea_inicio or l1 > u.linea_fin) for l1, l2 in por_archivo.get(rel, []))
            fila.update({"unidades": total, "semgrep_unidades_marcadas": marcadas,
                         "vulnminer_unidades_marcadas": vm.get("hallazgos")})
        else:
            det_sg = 0
            for v, dv in zip(spec["vulnerabilidades"], vm.get("detalle", [{}] * len(spec["vulnerabilidades"]))):
                u = unidad_de_linea(raiz, v["archivo"], v["linea"])
                ini, fin = (u.linea_inicio, u.linea_fin) if u else (v["linea"], v["linea"])
                reglas = sorted({h[3] for h in hallazgos if h[0] == v["archivo"] and not (h[2] < ini or h[1] > fin)})
                det_sg += bool(reglas)
                detalle.append({"proyecto": nombre, "id": v["id"], "nombre": v["nombre"],
                                "categorias": sorted(set(v["owasp2025"]) | set(v["api2023"])), "semgrep": bool(reglas),
                                "reglas_semgrep": reglas, "vulnminer": bool(dv.get("detectada"))})
            fila.update({"documentadas": len(spec["vulnerabilidades"]), "semgrep_detectadas": det_sg,
                         "vulnminer_detectadas": vm.get("detectadas")})
        filas.append(fila)
        log(f"semgrep {nombre:24s} {len(hallazgos):4d} hallazgos ({seg}s) | " +
            (f"detectadas semgrep={fila['semgrep_detectadas']}/{fila['documentadas']} vulnminer={fila['vulnminer_detectadas']}"
             if "documentadas" in fila else
             f"unidades marcadas semgrep={fila['semgrep_unidades_marcadas']}/{fila['unidades']} vulnminer={fila['vulnminer_unidades_marcadas']}"))
    return pd.DataFrame(filas), detalle


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep", default=shutil.which("semgrep"), help="ruta del ejecutable de semgrep")
    ap.add_argument("--sin-ablacion", action="store_true")
    args = ap.parse_args()
    verdad = json.loads((BASE / "evaluacion" / "verdad_terreno.json").read_text(encoding="utf-8"))
    salida_json = RESULTADOS / "contribucion_modelo.json"
    salida = json.loads(salida_json.read_text()) if salida_json.exists() else {}
    salida["fecha"] = datetime.now().isoformat(timespec="seconds")

    if not args.sin_ablacion:
        df = pd.read_csv(BASE / "datos" / "dataset.csv", keep_default_na=False)
        tr, va, te = (df[df.particion == p].reset_index(drop=True) for p in ("entrenamiento", "validacion", "prueba"))
        externos = unidades_externas(verdad)
        log(f"externo: {len(externos[0])} unidades vulnerables documentadas, {len(externos[1])} unidades limpias, "
            f"{len(externos[2])} del proyecto de demostración")
        abl = ablacion(tr, va, te, externos)
        abl.to_csv(RESULTADOS / "ablacion.csv", index=False)
        salida["ablacion"] = abl.to_dict(orient="records")

    if args.semgrep:
        version = subprocess.run([args.semgrep, "--version"], capture_output=True, text=True).stdout.strip()
        log(f"Semgrep {version} con las reglas comunitarias locales ({', '.join(LENGUAJES_SEMGREP)})")
        comp, detalle = comparar_semgrep(args.semgrep, verdad)
        comp.to_csv(RESULTADOS / "comparacion_semgrep.csv", index=False)
        vul = comp[comp.tipo == "vulnerable"]
        ref = comp[comp.tipo == "referencia"]
        salida["semgrep"] = {
            "version": version, "reglas": "semgrep-rules (" + ", ".join(LENGUAJES_SEMGREP) + ")",
            "proyectos": comp.to_dict(orient="records"), "detalle": detalle,
            "resumen": {"documentadas": int(vul.documentadas.sum()), "semgrep_detectadas": int(vul.semgrep_detectadas.sum()),
                        "vulnminer_detectadas": int(vul.vulnminer_detectadas.sum()),
                        "solo_vulnminer": sum(d["vulnminer"] and not d["semgrep"] for d in detalle if d["proyecto"] in set(vul.proyecto)),
                        "solo_semgrep": sum(d["semgrep"] and not d["vulnminer"] for d in detalle if d["proyecto"] in set(vul.proyecto)),
                        "ambas": sum(d["semgrep"] and d["vulnminer"] for d in detalle if d["proyecto"] in set(vul.proyecto)),
                        "union": sum(d["semgrep"] or d["vulnminer"] for d in detalle if d["proyecto"] in set(vul.proyecto)),
                        "unidades_limpias": int(ref.unidades.sum()),
                        "semgrep_unidades_limpias_marcadas": int(ref.semgrep_unidades_marcadas.sum()),
                        "vulnminer_unidades_limpias_marcadas": int(ref.vulnminer_unidades_marcadas.sum())}}
        r = salida["semgrep"]["resumen"]
        log(f"TOTAL documentadas={r['documentadas']} semgrep={r['semgrep_detectadas']} vulnminer={r['vulnminer_detectadas']} "
            f"ambas={r['ambas']} solo vulnminer={r['solo_vulnminer']} solo semgrep={r['solo_semgrep']} unión={r['union']} | "
            f"unidades limpias marcadas semgrep={r['semgrep_unidades_limpias_marcadas']} "
            f"vulnminer={r['vulnminer_unidades_limpias_marcadas']} de {r['unidades_limpias']}")
    else:
        log("semgrep no está instalado: se omite la comparación (pip install semgrep)")
    salida_json.write_text(json.dumps(salida, indent=2, ensure_ascii=False, default=float))


if __name__ == "__main__":
    main()

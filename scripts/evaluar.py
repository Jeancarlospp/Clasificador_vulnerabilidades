"""Fase ASSESS (parte funcional): evaluación sobre proyectos y fragmentos NO usados en el entrenamiento.

1. Proyectos de microservicios vulnerables con vulnerabilidades documentadas
   (evaluacion/verdad_terreno.json): se ejecuta la herramienta completa y se mide qué
   vulnerabilidades conocidas se detectan (sensibilidad) y si la categoría asignada coincide.
2. Proyectos de referencia sin vulnerabilidades intencionales: densidad de hallazgos
   (hallazgos por cada 100 unidades analizadas) como estimación de falsas alarmas.
3. Proyecto de demostración con la estructura del enunciado (vulnerabilidades sembradas; se informa aparte
   porque lo escribió el mismo autor del modelo).
4. Fragmentos de foros y documentación oficial (Stack Overflow, OWASP, Flask, Django...).

Salidas: resultados/evaluacion_externa.json y resultados/hallazgos_proyectos.csv

Uso: python scripts/evaluar.py
"""

import csv
import json
import sys
import warnings
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from vulnminer.analizador import analizar_proyecto, cargar_modelo  # noqa: E402
from vulnminer.segmentacion import Unidad, segmentar  # noqa: E402

warnings.filterwarnings("ignore")
RESULTADOS = BASE / "resultados"


def unidad_de_linea(raiz, archivo, linea):
    texto = (raiz / archivo).read_text(encoding="utf-8", errors="ignore")
    for u in segmentar(archivo, texto):
        if linea in u.lineas:
            return u
    return None


def evaluar_proyectos(modelo, verdad):
    resultados, filas_csv = {}, []
    for nombre, spec in verdad["proyectos"].items():
        raiz = BASE / spec["ruta"]
        if not raiz.exists():
            print(f"  (omitido {nombre}: ejecute scripts/descargar_fuentes.py)")
            continue
        r = analizar_proyecto(raiz, modelo)
        hallazgos = r["hallazgos"]
        for h in hallazgos:
            filas_csv.append({"proyecto": nombre, "id": h["id"], "microservicio": h["microservicio"], "archivo": h["archivo"],
                              "linea": h["linea"], "unidad": h["unidad"], "confianza": h["confianza"], "severidad": h["severidad"],
                              "owasp2025": ";".join(c["codigo"] for c in h["owasp_top10"]),
                              "api2023": ";".join(c["codigo"] for c in h["owasp_api"]),
                              "cwe": (h["cwe"] or {}).get("id", ""), "descripcion": h["descripcion"], "estado": h["estado"]})
        detalle, usados = [], set()
        for v in spec["vulnerabilidades"]:
            u = unidad_de_linea(raiz, v["archivo"], v["linea"])
            ini, fin = (u.linea_inicio, u.linea_fin) if u else (v["linea"], v["linea"])
            coinciden = [h for h in hallazgos if h["archivo"] == v["archivo"]
                         and not (h["linea_fin"] < ini or h["linea_inicio"] > fin)]
            esperadas = set(v["owasp2025"]) | set(v["api2023"])
            predichas = {c["codigo"] for h in coinciden for c in h["owasp_top10"] + h["owasp_api"]}
            usados.update(h["id"] for h in coinciden)
            detalle.append({"id": v["id"], "nombre": v["nombre"], "archivo": v["archivo"], "linea": v["linea"],
                            "detectada": bool(coinciden), "hallazgos": [h["id"] for h in coinciden],
                            "confianza": max((h["confianza"] for h in coinciden), default=0.0),
                            "categorias_esperadas": sorted(esperadas), "categorias_predichas": sorted(predichas),
                            "categoria_correcta": bool(esperadas & predichas),
                            "top10_correcta": bool(set(v["owasp2025"]) & predichas),
                            "api_correcta": (bool(set(v["api2023"]) & predichas) if v["api2023"] else None),
                            "lineas_unidad": [ini, fin]})
        n = len(detalle)
        det = sum(d["detectada"] for d in detalle)
        resultados[nombre] = {
            "tipo": spec["tipo"], "microservicios": r["resumen"]["microservicios"],
            "archivos": r["resumen"]["archivos_analizados"], "unidades": r["resumen"]["unidades_analizadas"],
            "hallazgos": len(hallazgos), "hallazgos_por_100_unidades": round(100 * len(hallazgos) / max(r["resumen"]["unidades_analizadas"], 1), 2),
            "vulnerabilidades_documentadas": n, "detectadas": det,
            "sensibilidad": round(det / n, 3) if n else None,
            "categoria_correcta": sum(d["categoria_correcta"] for d in detalle),
            "hallazgos_sobre_vulnerabilidades_documentadas": len(usados),
            "hallazgos_adicionales": len(hallazgos) - len(usados),
            "duracion_segundos": r["resumen"]["duracion_segundos"], "detalle": detalle,
        }
        txt = f"{det}/{n} detectadas, categoría correcta {resultados[nombre]['categoria_correcta']}/{n}" if n else "referencia"
        print(f"  {nombre:24s} {len(hallazgos):4d} hallazgos en {r['resumen']['unidades_analizadas']:5d} unidades | {txt}")
    return resultados, filas_csv


def metricas(y, p, umbral):
    y, p = np.array(y), np.array(p)
    yp = (p >= umbral).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, yp, labels=[0, 1]).ravel()
    return {"n": int(len(y)), "vulnerables": int(y.sum()), "precision": float(precision_score(y, yp, zero_division=0)),
            "recall": float(recall_score(y, yp, zero_division=0)), "f1": float(f1_score(y, yp, zero_division=0)),
            "accuracy": float((yp == y).mean()), "roc_auc": float(roc_auc_score(y, p)) if 0 < y.sum() < len(y) else None,
            "TP": int(tp), "FP": int(fp), "TN": int(tn), "FN": int(fn)}


def evaluar_fragmentos_web(modelo):
    ruta = BASE / "evaluacion" / "fragmentos_web.csv"
    if not ruta.exists():
        return None
    filas = list(csv.DictReader(ruta.open(encoding="utf-8")))
    unidades = []
    for r in filas:
        lineas = r["codigo"].splitlines()
        unidades.append(Unidad(r["id"], r["lenguaje"], "codigo", r["tipo"], list(range(1, len(lineas) + 1)), r["codigo"]))
    preds = modelo.predecir(unidades)
    y = [int(r["label"]) for r in filas]
    m = metricas(y, [q["probabilidad"] for q in preds], modelo.umbral)
    m["detalle"] = []
    for r, q in zip(filas, preds):
        cats = [c for c, _ in q["owasp2025"] + q["api2023"]]
        m["detalle"].append({"id": r["id"], "tipo": r["tipo"], "lenguaje": r["lenguaje"], "vulnerable": int(r["label"]),
                             "owasp_esperado": r["owasp"], "probabilidad": round(q["probabilidad"], 3),
                             "prediccion": int(q["vulnerable"]), "categorias": cats,
                             "categoria_correcta": (r["owasp"] in cats) if int(r["label"]) and q["vulnerable"] else None,
                             "fuente": r["fuente"]})
    return m


def main():
    RESULTADOS.mkdir(exist_ok=True)
    modelo = cargar_modelo()
    verdad = json.loads((BASE / "evaluacion" / "verdad_terreno.json").read_text(encoding="utf-8"))
    print("Proyectos de microservicios:")
    proyectos, filas = evaluar_proyectos(modelo, verdad)
    vul = [d for p in proyectos.values() if p["tipo"] == "vulnerable" for d in p["detalle"]]
    resumen = {"vulnerabilidades_documentadas": len(vul), "detectadas": sum(d["detectada"] for d in vul),
               "sensibilidad": round(sum(d["detectada"] for d in vul) / max(len(vul), 1), 3),
               "categoria_correcta": sum(d["categoria_correcta"] for d in vul),
               "categoria_correcta_sobre_detectadas": round(sum(d["categoria_correcta"] for d in vul) /
                                                             max(sum(d["detectada"] for d in vul), 1), 3)}
    por_categoria = defaultdict(lambda: {"documentadas": 0, "detectadas": 0, "categoria_correcta": 0})
    for d in vul:
        for c in d["categorias_esperadas"]:
            por_categoria[c]["documentadas"] += 1
            por_categoria[c]["detectadas"] += int(d["detectada"])
            por_categoria[c]["categoria_correcta"] += int(c in d["categorias_predichas"])
    web = evaluar_fragmentos_web(modelo)
    demo = [d for p in proyectos.values() if p["tipo"] == "demostracion" for d in p["detalle"]]
    resumen_demo = {"vulnerabilidades_sembradas": len(demo), "detectadas": sum(d["detectada"] for d in demo),
                    "categoria_correcta": sum(d["categoria_correcta"] for d in demo)}
    salida = {"umbral": modelo.umbral, "resumen_proyectos_vulnerables": resumen,
              "por_categoria": dict(sorted(por_categoria.items())), "proyectos": proyectos,
              "resumen_proyecto_demo": resumen_demo, "fragmentos_web": web}
    (RESULTADOS / "evaluacion_externa.json").write_text(json.dumps(salida, indent=2, ensure_ascii=False))
    if filas:
        with (RESULTADOS / "hallazgos_proyectos.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(filas[0]))
            w.writeheader()
            w.writerows(filas)
    print(f"\nVulnerabilidades documentadas detectadas: {resumen['detectadas']}/{resumen['vulnerabilidades_documentadas']} "
          f"(sensibilidad {resumen['sensibilidad']:.2f}); categoría correcta en {resumen['categoria_correcta']}")
    print(f"Proyecto de demostración: {resumen_demo['detectadas']}/{resumen_demo['vulnerabilidades_sembradas']} detectadas, "
          f"categoría correcta en {resumen_demo['categoria_correcta']}")
    for nombre, m in (("Fragmentos web", web),):
        if m:
            print(f"{nombre:15s} n={m['n']} P={m['precision']:.2f} R={m['recall']:.2f} F1={m['f1']:.2f} "
                  f"acc={m['accuracy']:.2f} AUC={m['roc_auc'] or 0:.2f}")


if __name__ == "__main__":
    main()

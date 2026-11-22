"""Genera las cifras y tablas del informe (informe/generado/*.tex) a partir de resultados/ y datos/.

Así el informe no contiene números copiados a mano: si se reentrena el modelo, basta con ejecutar
este script y recompilar el informe.

Uso: python scripts/generar_tablas_informe.py
"""

import json
import sys
from pathlib import Path

import pandas as pd

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))

from vulnminer import caracteristicas as C  # noqa: E402
from vulnminer.catalogo import API2023, OWASP2025, nombre_categoria  # noqa: E402
from vulnminer.modelo import NOMBRES_ALGORITMO  # noqa: E402

SALIDA = BASE / "informe" / "generado"


def num(x, d=3):
    return f"{x:.{d}f}".replace(".", "{,}")


def entero(x):
    return f"{int(x):,}".replace(",", "\\,")


def esc(t):
    return (str(t).replace("\\", "\\textbackslash{}").replace("&", "\\&").replace("%", "\\%").replace("_", "\\_")
            .replace("#", "\\#").replace("{", "\\{").replace("}", "\\}").replace("$", "\\$"))


def main():
    SALIDA.mkdir(parents=True, exist_ok=True)
    df = pd.read_csv(BASE / "datos" / "dataset.csv", keep_default_na=False)
    m = json.loads((BASE / "resultados" / "metricas.json").read_text())
    ext = json.loads((BASE / "resultados" / "evaluacion_externa.json").read_text())
    comp = pd.read_csv(BASE / "resultados" / "comparacion_detector.csv")
    comp_cat = pd.read_csv(BASE / "resultados" / "comparacion_categorias.csv")
    d, c = m["detector"], m["categorias"]
    r = ext["resumen_proyectos_vulnerables"]

    macros = {
        "nUnidades": entero(len(df)), "nVulnerables": entero(df.vulnerable.sum()), "nSeguras": entero((df.vulnerable == 0).sum()),
        "nEntrenamiento": entero((df.particion == "entrenamiento").sum()), "nValidacion": entero((df.particion == "validacion").sum()),
        "nPrueba": entero((df.particion == "prueba").sum()), "nGrupos": entero(df.proyecto.nunique()),
        "nBenignos": entero(df[df.fuente == "benigno"].proyecto.str.split("/").str[0].nunique()),
        "nControlados": entero((df.fuente == "casos-controlados").sum()),
        "detAlgoritmo": NOMBRES_ALGORITMO[d["algoritmo"]], "catAlgoritmo": NOMBRES_ALGORITMO[c["algoritmo"]],
        "detC": str(d["hiperparametros"].get("C", "")), "pesoSeguridad": num(m["representacion"]["peso_seguridad"], 0),
        "umbral": num(d["prueba"]["umbral"], 2),
        "pruebaPrecision": num(d["prueba"]["precision"]), "pruebaRecall": num(d["prueba"]["recall"]),
        "pruebaFUno": num(d["prueba"]["f1"]), "pruebaAUC": num(d["prueba"]["roc_auc"]), "pruebaAP": num(d["prueba"]["ap"]),
        "pruebaFPR": num(d["prueba"]["tasa_falsos_positivos"]), "pruebaExactitud": num(d["prueba"]["accuracy"]),
        "catMicro": num(c["prueba"]["f1_micro"]), "catMacro": num(c["prueba"]["f1_macro"]),
        "catMicroEE": num(c["prueba"]["f1_micro_extremo_a_extremo"]), "catMacroEE": num(c["prueba"]["f1_macro_extremo_a_extremo"]),
        "cweExactitud": num(m["cwe"]["exactitud_prueba"]), "nClasesCWE": str(len(m["cwe"]["clases"])),
        "nCategoriasEvaluadas": str(len(c["evaluadas"])),
        "extDocumentadas": str(r["vulnerabilidades_documentadas"]), "extDetectadas": str(r["detectadas"]),
        "extSensibilidad": num(r["sensibilidad"], 2), "extCategoria": str(r["categoria_correcta"]),
        "extCategoriaPct": f"{round(100 * r['categoria_correcta_sobre_detectadas'])}\\,\\%",
        "benignoExactitud": num(m["detector"]["por_fuente"].get("benigno", {}).get("accuracy", 0)),
        "benignoFPR": num(1 - m["detector"]["por_fuente"].get("benigno", {}).get("accuracy", 0)),
        "nIndicadores": str(len(C.NOMBRES_INDICADORES)), "nDerivadas": str(len(C.NOMBRES_DERIVADAS)),
        "nCaracteristicas": str(len(C.nombres_caracteristicas())),
        "nCWEtabla": str(len(pd.read_csv(BASE / "datos" / "correspondencias_cwe_owasp.csv"))),
        "nFamilias": str(len(json.loads((BASE / "datos" / "casos_controlados" / "manifiesto.json").read_text()) and
                             {x["familia"] for x in json.loads((BASE / "datos" / "casos_controlados" / "manifiesto.json").read_text())})),
        "dimTokens": entero(m["representacion"]["tokens"]), "dimCaracteres": entero(m["representacion"]["caracteres"]),
        "nCategoriasDatos": str(sum(1 for cat in list(OWASP2025) + list(API2023)
                                    if (df[df.vulnerable == 1].owasp2025 + ";" + df[df.vulnerable == 1].api2023).str.contains(cat + "(?!\\d)", regex=True).any())),
    }
    for nombre, clave in (("web", "fragmentos_web"), ("juice", "juice_shop")):
        e = ext.get(clave) or {}
        for k in ("precision", "recall", "f1", "accuracy"):
            macros[f"{nombre}{k.capitalize()}"] = num(e.get(k, 0))
        macros[f"{nombre}N"] = str(e.get("n", 0))
        macros[f"{nombre}AUC"] = num(e.get("roc_auc") or 0)
    for nombre, p in ext["proyectos"].items():
        clave = "".join(ch for ch in nombre.title() if ch.isalpha())
        macros[f"proy{clave}Hallazgos"] = str(p["hallazgos"])
        macros[f"proy{clave}Unidades"] = str(p["unidades"])
    (SALIDA / "cifras.tex").write_text("\n".join(f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in macros.items()) + "\n")

    # --- Tabla: composición del dataset por fuente
    t = df.groupby("fuente").agg(u=("id", "size"), v=("vulnerable", "sum")).sort_values("u", ascending=False)
    nombres_f = {"benigno": "Proyectos reales (código no vulnerable)", "codeql-tests": "Pruebas de consultas de CodeQL",
                 "semgrep-rules": "Pruebas de reglas de Semgrep", "owasp-benchmark-java": "OWASP Benchmark (Java)",
                 "owasp-benchmark-python": "OWASP Benchmark (Python)", "casos-controlados": "Casos controlados de API",
                 "kics": "Pruebas de KICS (Dockerfile, compose, OpenAPI)", "securityeval": "SecurityEval (Python)"}
    filas = [f"{esc(nombres_f.get(f, f))} & {entero(x.u)} & {entero(x.v)} & {entero(x.u - x.v)}\\\\" for f, x in t.iterrows()]
    filas.append(f"\\midrule\n\\textbf{{Total}} & \\textbf{{{entero(len(df))}}} & \\textbf{{{entero(df.vulnerable.sum())}}} & "
                 f"\\textbf{{{entero((df.vulnerable == 0).sum())}}}\\\\")
    (SALIDA / "tabla_fuentes.tex").write_text("\n".join(filas) + "\n")

    # --- Tabla: comparación del detector (mejor configuración por algoritmo)
    mejores = comp[comp.mejor_del_algoritmo].sort_values("val_ap", ascending=False)
    filas = []
    for k, (_, x) in enumerate(mejores.iterrows()):
        hp = ", ".join(f"{a}={b}" for a, b in json.loads(x.hiperparametros).items() if a != "n_estimators")
        celdas = [esc(x.nombre), esc(hp), num(x.val_ap), num(x.val_roc_auc), num(x.val_f1_umbral), num(x.prueba_f1), num(x.prueba_roc_auc)]
        if k == 0:
            celdas = [f"\\textbf{{{v}}}" for v in celdas]
        filas.append(" & ".join(celdas) + "\\\\")
    (SALIDA / "tabla_detector.tex").write_text("\n".join(filas) + "\n")

    # --- Tabla: comparación del categorizador
    filas = []
    for k, (_, x) in enumerate(comp_cat.sort_values("val_f1_macro", ascending=False).iterrows()):
        celdas = [esc(x.nombre), num(x.val_f1_micro), num(x.val_f1_macro), num(x.val_f1_macro_umbral05)]
        if k == 0:
            celdas = [f"\\textbf{{{v}}}" for v in celdas]
        filas.append(" & ".join(celdas) + "\\\\")
    (SALIDA / "tabla_categorizador.tex").write_text("\n".join(filas) + "\n")

    # --- Tabla: métricas por categoría en prueba
    filas = []
    for cat in list(OWASP2025) + list(API2023):
        x = c["por_categoria"].get(cat)
        if x is None:
            filas.append(f"{cat} & {esc(nombre_categoria(cat))} & \\multicolumn{{5}}{{l}}{{\\textit{{No evaluada: {esc(c['no_evaluadas'].get(cat, 'sin datos'))}}}}}\\\\")
            continue
        filas.append(f"{cat} & {esc(nombre_categoria(cat))} & {x['ejemplos_entrenamiento']} & {x['soporte_prueba']} & "
                     f"{num(x['precision'], 2)} & {num(x['recall'], 2)} & {num(x['f1'], 2)} / {num(x['f1_dado_vulnerable'], 2)}\\\\")
    (SALIDA / "tabla_categorias.tex").write_text("\n".join(filas) + "\n")

    # --- Tabla: proyectos de evaluación
    filas = []
    nombres_p = {"VAmPI": "VAmPI", "crAPI": "OWASP crAPI", "dvws-node": "dvws-node", "restaurant-api": "Damn Vulnerable RESTaurant",
                 "petclinic-microservices": "Spring PetClinic Microservices", "microservices-demo": "Online Boutique (Google)"}
    for nombre, p in ext["proyectos"].items():
        sens = f"{p['detectadas']}/{p['vulnerabilidades_documentadas']}" if p["vulnerabilidades_documentadas"] else "---"
        cat = f"{p['categoria_correcta']}/{p['vulnerabilidades_documentadas']}" if p["vulnerabilidades_documentadas"] else "---"
        filas.append(f"{esc(nombres_p.get(nombre, nombre))} & {p['microservicios']} & {p['archivos']} & {p['unidades']} & "
                     f"{p['hallazgos']} & {num(p['hallazgos_por_100_unidades'], 1)} & {sens} & {cat}\\\\")
    (SALIDA / "tabla_proyectos.tex").write_text("\n".join(filas) + "\n")

    # --- Tabla: detalle de vulnerabilidades documentadas
    filas = []
    for nombre, p in ext["proyectos"].items():
        for v in p["detalle"]:
            marca = "Sí" if v["detectada"] else "No"
            cats = ", ".join(v["categorias_predichas"]) or "---"
            filas.append(f"{esc(v['id'])} & {esc(v['nombre'])} & {', '.join(v['categorias_esperadas'])} & {marca} & "
                         f"{num(v['confianza'], 2) if v['detectada'] else '---'} & {esc(cats)}\\\\")
    (SALIDA / "tabla_detalle_externo.tex").write_text("\n".join(filas) + "\n")

    # --- Tabla: cobertura por categoría en proyectos no vistos
    filas = []
    for cat, x in ext["por_categoria"].items():
        filas.append(f"{cat} & {esc(nombre_categoria(cat))} & {x['documentadas']} & {x['detectadas']} & {x['categoria_correcta']}\\\\")
    (SALIDA / "tabla_cobertura_externa.tex").write_text("\n".join(filas) + "\n")
    print(f"Generados {len(list(SALIDA.glob('*.tex')))} archivos en {SALIDA.relative_to(BASE)}")


if __name__ == "__main__":
    main()

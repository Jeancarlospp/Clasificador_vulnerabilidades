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
    for nombre, clave in (("web", "fragmentos_web"),):
        e = ext.get(clave) or {}
        for k, sufijo in (("precision", "Precision"), ("recall", "Recall"), ("f1", "F"), ("accuracy", "Accuracy")):
            macros[f"{nombre}{sufijo}"] = num(e.get(k, 0))
        macros[f"{nombre}N"] = str(e.get("n", 0))
        macros[f"{nombre}AUC"] = num(e.get("roc_auc") or 0)
    for nombre, p in ext["proyectos"].items():
        clave = "".join(ch for ch in nombre.title() if ch.isalpha())
        macros[f"proy{clave}Hallazgos"] = str(p["hallazgos"])
        macros[f"proy{clave}Unidades"] = str(p["unidades"])
    demo = ext["resumen_proyecto_demo"]
    macros.update({"demoSembradas": str(demo["vulnerabilidades_sembradas"]), "demoDetectadas": str(demo["detectadas"]),
                   "demoCategoria": str(demo["categoria_correcta"]),
                   "nProyectosVulnerables": str(sum(p["tipo"] == "vulnerable" for p in ext["proyectos"].values()))})
    dv = m["desarrollo"]
    macros.update({"devPositivas": str(dv["con_umbral_operativo"]["positivas"]),
                   "devNegativas": entero(dv["con_umbral_operativo"]["negativas"]),
                   "devSensibilidad": num(dv["con_umbral_operativo"]["sensibilidad"], 2),
                   "devFA": num(100 * dv["con_umbral_operativo"]["falsas_alarmas"], 1) + "\\,\\%",
                   "devAUC": num(dv["con_umbral_operativo"]["auc"]),
                   "umbralValidacion": num(dv["umbral_validacion"], 2), "variante": esc(m["representacion"]["variante"])})
    # localización de la línea: distancia entre la línea documentada y la del hallazgo más cercano
    hp = pd.read_csv(BASE / "resultados" / "hallazgos_proyectos.csv", keep_default_na=False)
    distancias = []
    for nombre, p in ext["proyectos"].items():
        for v in p["detalle"]:
            if v["detectada"]:
                lineas = hp[(hp.proyecto == nombre) & hp.id.isin(v["hallazgos"])].linea
                distancias.append(min(abs(lineas - v["linea"])))
    distancias = pd.Series(distancias)
    macros.update({"locN": str(len(distancias)), "locCero": str(int((distancias == 0).sum())),
                   "locUno": str(int((distancias <= 1).sum())), "locTres": str(int((distancias <= 3).sum()))})
    cb = m.get("combinacion")
    if cb:
        macros.update({"combUbase": num(cb["umbral_base_codigo"], 2), "combUcomb": num(cb["umbral_combinado"], 2),
                       "combCoefP": num(cb["coeficientes"]["logit_probabilidad"], 2),
                       "combCoefE": num(cb["coeficientes"]["evidencia_estatica"], 2),
                       "combDevSens": num(cb["desarrollo_fuera_de_pliegue"]["sensibilidad"], 2),
                       "combDevFA": num(100 * cb["desarrollo_fuera_de_pliegue"]["falsas_alarmas"], 1) + "\\,\\%",
                       "combBaseDevSens": num(cb["desarrollo_modelo_base"]["sensibilidad"], 2),
                       "finalPrecision": num(cb["prueba"]["precision"]), "finalRecall": num(cb["prueba"]["recall"]),
                       "finalF": num(cb["prueba"]["f1"]), "finalFPR": num(cb["prueba"]["tasa_falsos_positivos"]),
                       "finalAUC": num(cb["prueba"]["roc_auc"])})
        sel = pd.read_csv(BASE / "resultados" / "seleccion_combinacion.csv")
        filas = []
        for _, x in sel.iterrows():
            celdas = [num(x.umbral_base_codigo, 2), num(x.umbral_combinado, 2), num(x.sensibilidad, 2),
                      num(100 * x.falsas_alarmas, 1)]
            if x.elegida:
                celdas = [f"\\textbf{{{v}}}" for v in celdas]
            filas.append(" & ".join(celdas) + "\\\\")
        (SALIDA / "tabla_combinacion.tex").write_text("\n".join(filas) + "\n")
    # sobreajuste: desempeño sobre una muestra de los datos de ajuste (misma muestra que el notebook 05)
    from sklearn.metrics import f1_score, roc_auc_score
    from vulnminer.analizador import cargar_modelo
    from vulnminer.modelo import a_unidades
    modelo = cargar_modelo()
    ajuste = df[df.particion.isin(["entrenamiento", "validacion"])]
    muestra = ajuste.sample(min(3000, len(ajuste)), random_state=1)
    pa = modelo.probabilidad(a_unidades(muestra))
    macros.update({"ajusteF": num(f1_score(muestra.vulnerable, pa >= modelo.umbral)),
                   "ajusteAUC": num(roc_auc_score(muestra.vulnerable, pa))})
    contrib_ruta = BASE / "resultados" / "contribucion_modelo.json"
    contrib = json.loads(contrib_ruta.read_text()) if contrib_ruta.exists() else {}
    for fila in contrib.get("ablacion", []):
        clave = "abl" + "".join(ch for ch in fila["clave"].title() if ch.isalpha())
        macros.update({f"{clave}F": num(fila["prueba_f1"]), f"{clave}Det": str(fila["ext_detectadas"]),
                       f"{clave}FA": num(100 * fila["ext_falsas_alarmas"], 1) + "\\,\\%",
                       f"{clave}Sens": num(fila["ext_sensibilidad_con_5pct_falsas_alarmas"], 2),
                       f"{clave}AUC": num(fila["ext_auc"])})
    if "semgrep" in contrib:
        rs = contrib["semgrep"]["resumen"]
        macros.update({"sgVersion": contrib["semgrep"]["version"], "sgDetectadas": str(rs["semgrep_detectadas"]),
                       "sgVulnminer": str(rs["vulnminer_detectadas"]), "sgAmbas": str(rs["ambas"]),
                       "sgSoloVulnminer": str(rs["solo_vulnminer"]), "sgSoloSemgrep": str(rs["solo_semgrep"]),
                       "sgUnion": str(rs["union"]), "sgUnidadesLimpias": str(rs["unidades_limpias"]),
                       "sgMarcadas": str(rs["semgrep_unidades_limpias_marcadas"]),
                       "sgMarcadasVm": str(rs["vulnminer_unidades_limpias_marcadas"])})
    invalidos = [k for k in macros if not k.isalpha()]
    assert not invalidos, f"nombres de macro no válidos en LaTeX: {invalidos}"
    (SALIDA / "cifras.tex").write_text("\n".join(f"\\newcommand{{\\{k}}}{{{v}}}" for k, v in macros.items()) + "\n")

    # --- Tabla: composición del dataset por fuente
    t = df.groupby("fuente").agg(u=("id", "size"), v=("vulnerable", "sum")).sort_values("u", ascending=False)
    nombres_f = {"benigno": "Proyectos reales (código no vulnerable)", "codeql-tests": "Pruebas de consultas de CodeQL",
                 "semgrep-rules": "Pruebas de reglas de Semgrep", "owasp-benchmark-java": "OWASP Benchmark (Java)",
                 "owasp-benchmark-python": "OWASP Benchmark (Python)", "casos-controlados": "Casos controlados de API",
                 "kics": "Pruebas de KICS (Dockerfile, compose, OpenAPI)", "securityeval": "SecurityEval (Python)",
                 "juice-shop": "OWASP Juice Shop (retos de corrección de código)",
                 "vulnerableapp": "OWASP VulnerableApp (niveles por vulnerabilidad)"}
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
            import re
            n_ej = re.search(r"\((\d+) ejemplos", c["no_evaluadas"].get(cat, ""))
            motivo = (f"{n_ej.group(1)} ejemplo{'' if n_ej.group(1) == '1' else 's'} de entrenamiento" if n_ej else "sin datos")
            filas.append(f"{cat} & {esc(nombre_categoria(cat))} & \\multicolumn{{5}}{{l}}{{\\textit{{No evaluada ({motivo})}}}}\\\\")
            continue
        filas.append(f"{cat} & {esc(nombre_categoria(cat))} & {x['ejemplos_entrenamiento']} & {x['soporte_prueba']} & "
                     f"{num(x['precision'], 2)} & {num(x['recall'], 2)} & {num(x['f1'], 2)} / {num(x['f1_dado_vulnerable'], 2)}\\\\")
    (SALIDA / "tabla_categorias.tex").write_text("\n".join(filas) + "\n")

    # --- Tabla: proyectos de evaluación (vulnerables, demostración y referencia)
    nombres_p = {"VAmPI": "VAmPI", "crAPI": "OWASP crAPI", "dvws-node": "dvws-node", "restaurant-api": "Damn Vulnerable RESTaurant",
                 "VRPlayground": "VRPlayground", "proyecto-demo": "Proyecto de demostración (propio)",
                 "petclinic-microservices": "Spring PetClinic Microservices", "microservices-demo": "Online Boutique (Google)"}
    filas = []
    for tipo in ("vulnerable", "demostracion", "referencia"):
        grupo = [(n, p) for n, p in ext["proyectos"].items() if p["tipo"] == tipo]
        if filas and grupo:
            filas.append("\\midrule")
        for nombre, p in grupo:
            sens = f"{p['detectadas']}/{p['vulnerabilidades_documentadas']}" if p["vulnerabilidades_documentadas"] else "---"
            cat = f"{p['categoria_correcta']}/{p['vulnerabilidades_documentadas']}" if p["vulnerabilidades_documentadas"] else "---"
            filas.append(f"{esc(nombres_p.get(nombre, nombre))} & {p['microservicios']} & {p['archivos']} & {p['unidades']} & "
                         f"{p['hallazgos']} & {num(p['hallazgos_por_100_unidades'], 1)} & {sens} & {cat}\\\\")
    (SALIDA / "tabla_proyectos.tex").write_text("\n".join(filas) + "\n")

    # --- Tabla: ablación
    if contrib.get("ablacion"):
        filas = []
        for fila in contrib["ablacion"]:
            celdas = [esc(fila["variante"]), str(fila["variables"]), num(fila["prueba_f1"]), num(fila["prueba_roc_auc"]),
                      f"{fila['ext_detectadas']}/{fila['ext_documentadas']}", num(100 * fila["ext_falsas_alarmas"], 1),
                      num(fila["ext_auc"]), num(fila["ext_sensibilidad_con_5pct_falsas_alarmas"], 2)]
            if fila["clave"] == "herramienta":
                celdas = [f"\\textbf{{{v}}}" for v in celdas]
            filas.append(" & ".join(celdas) + "\\\\")
        (SALIDA / "tabla_ablacion.tex").write_text("\n".join(filas) + "\n")

    # --- Tabla: comparación con Semgrep
    if "semgrep" in contrib:
        filas = []
        for x in contrib["semgrep"]["proyectos"]:
            n = esc(nombres_p.get(x["proyecto"], x["proyecto"]))
            if x["tipo"] == "referencia":
                filas.append(f"{n} & --- & {int(x['semgrep_unidades_marcadas'])}/{int(x['unidades'])} & "
                             f"{int(x['vulnminer_unidades_marcadas'])}/{int(x['unidades'])} & "
                             f"{x['semgrep_hallazgos']} & {x['vulnminer_hallazgos']}\\\\")
            else:
                filas.append(f"{n} & {int(x['documentadas'])} & {int(x['semgrep_detectadas'])} & {int(x['vulnminer_detectadas'])} & "
                             f"{x['semgrep_hallazgos']} & {x['vulnminer_hallazgos']}\\\\")
        (SALIDA / "tabla_semgrep.tex").write_text("\n".join(filas) + "\n")

    # --- Tabla: selección de la variante de la representación (conjunto de desarrollo)
    var = pd.read_csv(BASE / "resultados" / "seleccion_variante.csv")
    filas = []
    for k, (_, x) in enumerate(var.iterrows()):
        celdas = [esc(x.variante), num(x.peso_seguridad, 0), num(x.val_ap), num(x.dev_ap), num(x.dev_auc), num(x.dev_sensibilidad_5pct, 2)]
        if k == 0:
            celdas = [f"\\textbf{{{v}}}" for v in celdas]
        filas.append(" & ".join(celdas) + "\\\\")
    (SALIDA / "tabla_variantes.tex").write_text("\n".join(filas) + "\n")

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

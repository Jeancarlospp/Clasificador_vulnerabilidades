# %% [markdown]
# # Fase 5 · ASSESS — Evaluación del modelo
#
# **Objetivo:** evaluar la capacidad del modelo para clasificar posibles vulnerabilidades y determinar sus
# limitaciones con datos y proyectos **no utilizados en el entrenamiento**.
#
# 1. Partición de **prueba** (15 %, grupos de origen nunca vistos): métricas, matriz de confusión, curvas.
# 2. Desempeño **por categoría OWASP** (multietiqueta: F1 micro, F1 macro y matrices por categoría).
# 3. Análisis de **falsos positivos y falsos negativos**.
# 4. **Sobreajuste** y generalización.
# 5. Pruebas funcionales de la herramienta sobre **proyectos de microservicios** reales no vistos y sobre
#    fragmentos externos (`scripts/evaluar.py`).
# 6. **Contribución del modelo**: ablación frente a las reglas solas y comparación con Semgrep
#    (`scripts/contribucion.py`).

# %%
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (ConfusionMatrixDisplay, average_precision_score, confusion_matrix, f1_score,
                             precision_recall_curve, roc_auc_score, roc_curve)

BASE = Path.cwd().parent if Path.cwd().name == "notebooks" else Path.cwd()
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "notebooks"))
import estilo as E  # noqa: E402
from vulnminer.catalogo import nombre_categoria  # noqa: E402
from vulnminer.modelo import ModeloVulnminer, a_unidades  # noqa: E402

E.aplicar()
pd.set_option("display.max_colwidth", 70)
df = pd.read_csv(BASE / "datos" / "dataset.csv", keep_default_na=False)
te = df[df.particion == "prueba"].reset_index(drop=True)
modelo = ModeloVulnminer.cargar(BASE / "vulnminer" / "modelos" / "vulnminer.joblib")
metricas = json.loads((BASE / "resultados" / "metricas.json").read_text())
externa = json.loads((BASE / "resultados" / "evaluacion_externa.json").read_text())
print(f"Prueba: {len(te):,} unidades de {te.proyecto.nunique()} grupos de origen no vistos | vulnerables: {te.vulnerable.sum():,}")

# %% [markdown]
# ## 1. Detector en la partición de prueba
#
# Las métricas de esta sección son las del **modelo base** (sección 4 del notebook 04). La última fila de la
# tabla muestra la **decisión final** de la herramienta, que añade la etapa de combinación descrita en la
# sección 7.

# %%
X = modelo.transformar(a_unidades(te))
p = modelo.probabilidad(X=X)
y = te.vulnerable.values
yp = (p >= modelo.umbral).astype(int)
m = metricas["detector"]["prueba"]
mv = metricas["detector"]["prueba_umbral_validacion"]
fila = lambda x: {"Umbral": x["umbral"], "Precisión": x["precision"], "Sensibilidad (recall)": x["recall"], "F1": x["f1"],  # noqa: E731
                  "Exactitud": x["accuracy"], "AUC-ROC": x["roc_auc"], "Precisión promedio (AP)": x["ap"],
                  "Tasa de falsos positivos": x["tasa_falsos_positivos"]}
mf = dict(metricas["combinacion"]["prueba"], umbral=f"{metricas['combinacion']['umbral_base_codigo']} / {metricas['combinacion']['umbral_combinado']}")
pd.DataFrame({"Modelo base (umbral operativo)": fila(m), "Modelo base (umbral de validación)": fila(mv),
              "Decisión final de la herramienta (con combinación)": fila(mf)}).T

# %%
fig, axes = plt.subplots(1, 3, figsize=(13, 3.9))
cm = confusion_matrix(y, yp)
ConfusionMatrixDisplay(cm, display_labels=["No vulnerable", "Vulnerable"]).plot(ax=axes[0], cmap="Blues", colorbar=False, values_format="d")
axes[0].set_title("Matriz de confusión")
axes[0].grid(False)
fpr, tpr, _ = roc_curve(y, p)
axes[1].plot(fpr, tpr, color=E.AZUL, linewidth=2, label=f"AUC = {roc_auc_score(y, p):.3f}")
axes[1].plot([0, 1], [0, 1], color=E.TEXTO_2, linestyle="--", linewidth=1)
axes[1].set_xlabel("Tasa de falsos positivos")
axes[1].set_ylabel("Tasa de verdaderos positivos")
axes[1].set_title("Curva ROC")
axes[1].legend(loc="lower right")
prec, rec, _ = precision_recall_curve(y, p)
axes[2].plot(rec, prec, color=E.NARANJA, linewidth=2, label=f"AP = {average_precision_score(y, p):.3f}")
axes[2].axhline(y.mean(), color=E.TEXTO_2, linestyle="--", linewidth=1)
axes[2].set_xlabel("Sensibilidad")
axes[2].set_ylabel("Precisión")
axes[2].set_title("Curva precisión–sensibilidad")
axes[2].legend(loc="lower left")
fig.tight_layout()
E.guardar(fig, "evaluacion_prueba")
plt.show()

# %% [markdown]
# ### Desempeño por fuente, lenguaje y tipo de archivo

# %%
def tabla_grupo(clave):
    t = pd.DataFrame(metricas["detector"][clave]).T[["n", "vulnerables", "accuracy", "precision", "recall", "f1"]]
    return t.astype({"n": int, "vulnerables": int}).round(3).sort_values("n", ascending=False)

tabla_grupo("por_fuente")

# %%
pd.concat([tabla_grupo("por_lenguaje"), tabla_grupo("por_subtipo")])

# %% [markdown]
# ## 2. Desempeño por categoría OWASP
#
# Dos vistas complementarias:
#
# - **Extremo a extremo:** la unidad debe detectarse como vulnerable *y* recibir la categoría correcta. Es lo
#   que experimenta el usuario de la herramienta.
# - **Dado que es vulnerable:** calidad del categorizador por sí solo, sobre las unidades realmente vulnerables.

# %%
pc = pd.DataFrame(metricas["categorias"]["por_categoria"]).T
pc.insert(0, "categoria", [nombre_categoria(c) for c in pc.index])
cols = ["categoria", "ejemplos_entrenamiento", "soporte_prueba", "precision", "recall", "f1", "f1_dado_vulnerable"]
tabla_cat = pc[cols].copy()
for c in cols[3:]:
    tabla_cat[c] = tabla_cat[c].astype(float).round(3)
tabla_cat

# %%
cm_ = metricas["categorias"]["prueba"]
pd.Series({"F1 micro (dado vulnerable)": cm_["f1_micro"], "F1 macro (dado vulnerable)": cm_["f1_macro"],
           "F1 micro (extremo a extremo)": cm_["f1_micro_extremo_a_extremo"],
           "F1 macro (extremo a extremo)": cm_["f1_macro_extremo_a_extremo"],
           "Hallazgos pendientes de revisión (sin categoría)": cm_["hallazgos_pendientes_de_revision"],
           "Exactitud del CWE (prueba)": metricas["cwe"]["exactitud_prueba"]}).round(3).to_frame("valor")

# %%
orden = pc.sort_values("f1_dado_vulnerable", ascending=True)
fig, ax = plt.subplots(figsize=(9, 6))
yy = np.arange(len(orden))
ax.barh(yy + 0.2, orden["f1_dado_vulnerable"].astype(float), height=0.38, color=E.AZUL, label="Dado que es vulnerable")
ax.barh(yy - 0.2, orden["f1"].astype(float), height=0.38, color=E.NARANJA, label="Extremo a extremo")
ax.set_yticks(yy, [f"{c} (n={int(s)})" for c, s in zip(orden.index, orden.soporte_prueba)])
ax.set_xlim(0, 1)
ax.set_xlabel("F1 en prueba")
ax.set_title("F1 por categoría OWASP (n = unidades de prueba)")
h, l = ax.get_legend_handles_labels()
ax.legend(h[::-1], l[::-1], loc="lower right")
fig.tight_layout()
E.guardar(fig, "evaluacion_categorias")
plt.show()

# %% [markdown]
# ### Matrices de confusión por categoría (extremo a extremo)

# %%
principales = [c for c in pc.sort_values("soporte_prueba", ascending=False).index[:8]]
fig, axes = plt.subplots(2, 4, figsize=(13, 6))
for ax, c in zip(axes.ravel(), principales):
    mc = np.array(pc.loc[c, "matriz_confusion"])
    ConfusionMatrixDisplay(mc, display_labels=["no", "sí"]).plot(ax=ax, cmap="Blues", colorbar=False, values_format="d")
    ax.set_title(c, fontsize=10)
    ax.grid(False)
    ax.set_xlabel("Predicho")
    ax.set_ylabel("Real")
fig.tight_layout()
E.guardar(fig, "evaluacion_matrices_categoria")
plt.show()

# %% [markdown]
# ## 3. Análisis de falsos positivos y falsos negativos

# %%
pred = pd.read_csv(BASE / "resultados" / "predicciones_prueba.csv", keep_default_na=False)
pred["error"] = np.where((pred.vulnerable == 1) & (pred.prediccion == 0), "falso negativo",
                         np.where((pred.vulnerable == 0) & (pred.prediccion == 1), "falso positivo", "acierto"))
errores = pd.crosstab(pred.fuente, pred.error)
errores

# %%
fn = pred[pred.error == "falso negativo"]
fn_cat = fn.owasp2025.str.split(";").explode().value_counts()
tot_cat = pred[pred.vulnerable == 1].owasp2025.str.split(";").explode().value_counts()
(fn_cat / tot_cat).dropna().sort_values(ascending=False).round(2).to_frame("tasa de falsos negativos por categoría")

# %%
def mostrar(fila, n_lineas=14):
    reg = te[te.id == fila.id].iloc[0]
    u = a_unidades(te[te.id == fila.id])[0]
    u.lineas = list(range(reg.linea_inicio, reg.linea_inicio + len(reg.codigo.splitlines())))
    rel = modelo.lineas_relevantes(u)
    print(f"[{fila.error}] {fila.fuente} · {fila.archivo} · {fila.unidad} | P={fila.probabilidad:.3f} | "
          f"real: {fila.owasp2025 or 'no vulnerable'} {fila.cwe} | predicho: {fila.categorias_predichas or '-'}")
    print("líneas más influyentes:", [(l, round(c, 3)) for l, c in rel])
    print("\n".join(reg.codigo.splitlines()[:n_lineas]), "\n")

for _, f in pred[pred.error == "falso positivo"].sort_values("probabilidad", ascending=False).head(4).iterrows():
    mostrar(f)

# %%
for _, f in pred[pred.error == "falso negativo"].sort_values("probabilidad").head(4).iterrows():
    mostrar(f)

# %% [markdown]
# ## 4. Sobreajuste y generalización

# %%
entreno = df[df.particion.isin(["entrenamiento", "validacion"])]
muestra = entreno.sample(min(3000, len(entreno)), random_state=1)
pe = modelo.probabilidad(a_unidades(muestra))
filas = {
    "Datos de ajuste (entren. + valid.)": [f1_score(muestra.vulnerable, pe >= modelo.umbral), roc_auc_score(muestra.vulnerable, pe)],
    "Prueba (grupos no vistos)": [m["f1"], m["roc_auc"]],
}
web = externa.get("fragmentos_web")
if web:
    filas["Fragmentos de foros y documentación"] = [web["f1"], web["roc_auc"]]
gen = pd.DataFrame(filas, index=["F1", "AUC-ROC"]).T.round(3)
gen

# %% [markdown]
# La diferencia entre los datos de ajuste y la prueba muestra el grado de sobreajuste. El modelo memoriza
# parte de los ejemplos de entrenamiento (como cualquier modelo léxico de alta dimensión), pero conserva
# un desempeño útil sobre proyectos y fuentes que nunca vio.

# %% [markdown]
# ## 5. Prueba funcional sobre proyectos de microservicios no vistos
#
# La herramienta completa (`vulnminer scan`) se ejecutó sobre cinco proyectos vulnerables con
# vulnerabilidades documentadas (crAPI de OWASP, VAmPI, dvws-node, Damn Vulnerable RESTaurant y
# VRPlayground) y sobre dos
# proyectos de referencia sin vulnerabilidades intencionales (Spring PetClinic Microservices y Online
# Boutique de Google). Una vulnerabilidad documentada se cuenta como **detectada** si algún hallazgo cae en
# la función que la contiene.

# %%
proy = pd.DataFrame({k: {c: v[c] for c in ("tipo", "microservicios", "archivos", "unidades", "hallazgos",
                                            "hallazgos_por_100_unidades", "vulnerabilidades_documentadas", "detectadas",
                                            "sensibilidad", "categoria_correcta")}
                     for k, v in externa["proyectos"].items()}).T
proy

# %%
r = externa["resumen_proyectos_vulnerables"]
print(f"Vulnerabilidades documentadas detectadas: {r['detectadas']}/{r['vulnerabilidades_documentadas']} "
      f"(sensibilidad {r['sensibilidad']:.2f}); con categoría correcta: {r['categoria_correcta']} "
      f"({r['categoria_correcta_sobre_detectadas']:.0%} de las detectadas)")
det = pd.DataFrame([d | {"proyecto": k} for k, v in externa["proyectos"].items() for d in v["detalle"]])
det[["proyecto", "id", "nombre", "detectada", "confianza", "categorias_esperadas", "categorias_predichas", "categoria_correcta"]]

# %%
porcat = pd.DataFrame(externa["por_categoria"]).T
porcat["sensibilidad"] = (porcat.detectadas / porcat.documentadas).round(2)
porcat["categoria_correcta_%"] = (porcat.categoria_correcta / porcat.documentadas * 100).round(0)
porcat.insert(0, "categoria", [nombre_categoria(c) for c in porcat.index])
porcat

# %%
fig, ax = plt.subplots(figsize=(9, 4.2))
pv = proy[proy.tipo.isin(["vulnerable", "demostracion"])]
x = np.arange(len(pv))
b1 = ax.bar(x - 0.2, pv.vulnerabilidades_documentadas.astype(int), width=0.38, color=E.TEXTO_2, alpha=0.35, label="Documentadas")
b2 = ax.bar(x + 0.2, pv.detectadas.astype(int), width=0.38, color=E.NARANJA, label="Detectadas")
E.etiquetar_barras(ax, b1)
E.etiquetar_barras(ax, b2)
ax.set_xticks(x, pv.index)
ax.set_ylabel("Vulnerabilidades")
ax.set_title("Vulnerabilidades documentadas detectadas por proyecto")
ax.legend()
fig.tight_layout()
E.guardar(fig, "evaluacion_proyectos")
plt.show()

# %% [markdown]
# El proyecto de demostración (estructura del enunciado: gateway, NestJS, Spring Boot y FastAPI) lo escribí
# para el laboratorio con vulnerabilidades sembradas; se informa aparte porque comparte autor con los casos
# controlados y, por tanto, es una estimación optimista.

# %%
externa["resumen_proyecto_demo"]

# %% [markdown]
# ### Fragmentos externos

# %%
filas = []
for nombre, mm in (("Fragmentos de foros y documentación", web),):
    if mm:
        filas.append({"conjunto": nombre, "n": mm["n"], "vulnerables": mm["vulnerables"], "precision": mm["precision"],
                      "recall": mm["recall"], "f1": mm["f1"], "accuracy": mm["accuracy"], "auc": mm["roc_auc"]})
pd.DataFrame(filas).round(3)

# %%
if web:
    w = pd.DataFrame(web["detalle"])
    w["acierto"] = w.vulnerable == w.prediccion
    display(w[["id", "tipo", "lenguaje", "vulnerable", "probabilidad", "prediccion", "acierto", "categorias", "owasp_esperado"]])

# %% [markdown]
# ## 6. Contribución del modelo de clasificación
#
# El enunciado permite usar reglas o herramientas existentes **siempre que se evidencie la contribución del
# modelo**. Para medirla hice dos experimentos (`scripts/contribucion.py`):
#
# **a) Ablación.** Con el mismo algoritmo del detector final (SVM lineal calibrada, C = 1) y el mismo
# protocolo (umbral de máximo F1 en validación y reentrenamiento con entrenamiento + validación) comparé:
#
# - **Reglas solas**: sin aprendizaje; una unidad es vulnerable si activa al menos *k* indicadores de operación
#   peligrosa. Uso dos versiones: *k* elegido en validación (mismo criterio que el umbral del modelo) y *k*
#   calibrado en el conjunto de desarrollo con 5 % de falsas alarmas (mismo criterio que el umbral operativo).
# - **Solo indicadores** de análisis estático con el clasificador (y con Random Forest, por si las variables
#   necesitaran un modelo no lineal).
# - **Solo texto**: TF-IDF de tokens y de caracteres.
# - **Modelo completo**: texto + indicadores (el modelo base de la herramienta).
# - **Modelo completo + combinación**: la decisión final de la herramienta (sección 7).
#
# En los proyectos externos la comparación se hace a nivel de unidad: las 66 funciones con vulnerabilidades
# documentadas frente a todas las unidades de los proyectos limpios (PetClinic y Online Boutique). Como cada
# variante tiene su propio umbral, también informo la **sensibilidad con 5 % de falsas alarmas**, que compara
# las variantes en el mismo punto de operación.

# %%
contrib = json.loads((BASE / "resultados" / "contribucion_modelo.json").read_text())
abl = pd.DataFrame(contrib["ablacion"]).set_index("variante")
tabla_abl = pd.DataFrame({
    "Variables": abl.variables, "Umbral": abl.umbral,
    "Prueba: precisión": abl.prueba_precision, "Prueba: sensibilidad": abl.prueba_recall, "Prueba: F1": abl.prueba_f1,
    "Prueba: AUC": abl.prueba_roc_auc,
    "Externo: detectadas": abl.ext_detectadas.astype(int).astype(str) + "/" + abl.ext_documentadas.astype(int).astype(str),
    "Externo: falsas alarmas": abl.ext_falsas_alarmas, "Externo: AUC": abl.ext_auc,
    "Externo: sensibilidad con 5 % FA": abl.ext_sensibilidad_con_5pct_falsas_alarmas,
    "Demo: detectadas": abl.ext_demo_detectadas.astype(int).astype(str) + "/" + abl.ext_demo_sembradas.astype(int).astype(str)})
tabla_abl.round(3)

# %%
cortos = {"reglas": "Reglas (k de validación)", "reglas_desarrollo": "Reglas (k de desarrollo)",
          "indicadores": "Solo indicadores", "indicadores_rf": "Indicadores + RF", "tfidf": "Solo texto (TF-IDF)",
          "completo": "Modelo completo", "herramienta": "Modelo + combinación"}
a = pd.DataFrame(contrib["ablacion"]).set_index("clave").loc[list(cortos)]
fig, axes = plt.subplots(1, 2, figsize=(12.5, 3.9))
yy = np.arange(len(a))[::-1]
colores = [E.NARANJA if k == "herramienta" else E.AZUL if k == "completo" else E.TEXTO_2 for k in a.index]
for ax, col, titulo in ((axes[0], "prueba_f1", "F1 en la partición de prueba"),
                        (axes[1], "ext_sensibilidad_con_5pct_falsas_alarmas",
                         "Proyectos externos: sensibilidad con 5 % de falsas alarmas")):
    barras = ax.barh(yy, a[col].astype(float), color=colores, alpha=0.9, height=0.6)
    E.etiquetar_barras(ax, barras, "{:.2f}", horizontal=True)
    ax.set_yticks(yy, [cortos[k] for k in a.index])
    ax.set_xlim(0, 1.05)
    ax.set_title(titulo)
    ax.grid(axis="y", visible=False)
fig.tight_layout()
E.guardar(fig, "contribucion_ablacion")
plt.show()

# %% [markdown]
# **Lectura de la ablación.**
#
# - En la partición de prueba, que mide si el modelo distingue un caso vulnerable de su versión corregida, el
#   aprendizaje aporta mucho: las reglas y los indicadores solos quedan muy por debajo del texto y del modelo
#   completo.
# - En los proyectos reales ocurre algo distinto. Con *k* calibrado en desarrollo, las reglas solas detectan
#   más vulnerabilidades que el modelo base con una tasa de falsas alarmas parecida. La razón es un **cambio de
#   distribución**: en los datos de entrenamiento la versión vulnerable y la segura de un caso tienen casi las
#   mismas operaciones peligrosas, por lo que el modelo aprendió a no dar peso a la *cantidad* de evidencia;
#   en las aplicaciones reales, las funciones vulnerables suelen acumular varias operaciones peligrosas.
#
# Este resultado motivó una iteración Assess → Modify/Model: la etapa de combinación de la sección 7.

# %% [markdown]
# **b) Comparación con Semgrep.** Semgrep es un analizador estático por reglas muy usado. Lo ejecuté con las
# reglas comunitarias de su repositorio (`semgrep-rules`, las mismas cuyos casos de prueba forman parte del
# dataset) sobre los mismos proyectos y con el mismo criterio de acierto: un hallazgo dentro de la función
# documentada. En los proyectos limpios cuento las unidades de análisis que contienen algún hallazgo.

# %%
sg = contrib["semgrep"]
comp_sg = pd.DataFrame(sg["proyectos"]).set_index("proyecto")
vul = comp_sg[comp_sg.tipo != "referencia"][["documentadas", "semgrep_detectadas", "vulnminer_detectadas",
                                             "semgrep_hallazgos", "vulnminer_hallazgos"]].astype(int)
ref = comp_sg[comp_sg.tipo == "referencia"][["unidades", "semgrep_unidades_marcadas", "vulnminer_unidades_marcadas",
                                             "semgrep_hallazgos", "vulnminer_hallazgos"]].astype(int)
print(f"Semgrep {sg['version']} — reglas: {sg['reglas']}")
display(vul)
display(ref)
pd.Series(sg["resumen"]).to_frame("total")

# %%
fig, axes = plt.subplots(1, 2, figsize=(12.5, 3.9), gridspec_kw={"width_ratios": [2.2, 1]})
x = np.arange(len(vul))
b0 = axes[0].bar(x - 0.27, vul.documentadas, width=0.26, color=E.TEXTO_2, alpha=0.3, label="Documentadas")
b1 = axes[0].bar(x, vul.semgrep_detectadas, width=0.26, color=E.AZUL, label="Semgrep")
b2 = axes[0].bar(x + 0.27, vul.vulnminer_detectadas, width=0.26, color=E.NARANJA, label="vulnminer")
for b in (b0, b1, b2):
    E.etiquetar_barras(axes[0], b)
axes[0].set_xticks(x, vul.index)
axes[0].set_ylabel("Vulnerabilidades")
axes[0].set_title("Vulnerabilidades documentadas detectadas")
axes[0].legend()
xr = np.arange(len(ref))
t1 = axes[1].bar(xr - 0.18, 100 * ref.semgrep_unidades_marcadas / ref.unidades, width=0.34, color=E.AZUL, label="Semgrep")
t2 = axes[1].bar(xr + 0.18, 100 * ref.vulnminer_unidades_marcadas / ref.unidades, width=0.34, color=E.NARANJA, label="vulnminer")
for b in (t1, t2):
    E.etiquetar_barras(axes[1], b, "{:.1f}")
axes[1].set_xticks(xr, ["PetClinic", "Online Boutique"])
axes[1].set_ylabel("% de unidades marcadas")
axes[1].set_title("Proyectos limpios: unidades marcadas")
fig.tight_layout()
E.guardar(fig, "contribucion_semgrep")
plt.show()

# %%
det_sg = pd.DataFrame(sg["detalle"])
det_sg["resultado"] = np.select([det_sg.semgrep & det_sg.vulnminer, det_sg.vulnminer, det_sg.semgrep],
                                ["ambas", "solo vulnminer", "solo Semgrep"], "ninguna")
display(pd.crosstab(det_sg.proyecto, det_sg.resultado))
det_sg[det_sg.resultado.isin(["solo vulnminer", "solo Semgrep"])][["proyecto", "id", "nombre", "categorias", "resultado", "reglas_semgrep"]]

# %% [markdown]
# ## 7. Iteración: etapa de combinación con la evidencia estática
#
# Con el conjunto de **desarrollo** (aplicaciones reales, separado del entrenamiento y de la evaluación) ajusté
# una regresión logística de dos variables: el logit de la probabilidad del modelo base y el número de
# indicadores de operación peligrosa activos (`scripts/combinar.py`). Se aplica solo al código de servidor,
# porque el conjunto de desarrollo no tiene vulnerabilidades de configuración ni de frontend.
#
# En el código, una unidad es vulnerable si el modelo base está seguro (*p* ≥ u_base) **o** la probabilidad
# combinada supera u_comb. Los umbrales se eligieron con predicciones fuera de pliegue (validación cruzada de
# 5 pliegues) manteniendo 5 % de falsas alarmas: la mayor sensibilidad y, dentro de una tolerancia de una
# vulnerabilidad, la opción que más respeta al modelo base.

# %%
comb = metricas["combinacion"]
sel = pd.read_csv(BASE / "resultados" / "seleccion_combinacion.csv")
print("Coeficientes:", comb["coeficientes"], "| intercepto:", round(comb["intercepto"], 3))
print(f"Modelo base solo en desarrollo: sensibilidad {comb['desarrollo_modelo_base']['sensibilidad']:.2f}, "
      f"falsas alarmas {comb['desarrollo_modelo_base']['falsas_alarmas']:.3f}")
sel.round(3)

# %%
efecto = pd.DataFrame({
    "Prueba: F1": [m["f1"], comb["prueba"]["f1"]],
    "Prueba: precisión": [m["precision"], comb["prueba"]["precision"]],
    "Prueba: sensibilidad": [m["recall"], comb["prueba"]["recall"]],
    "Desarrollo: sensibilidad con 5 % FA": [comb["desarrollo_modelo_base"]["sensibilidad"],
                                            comb["desarrollo_fuera_de_pliegue"]["sensibilidad"]],
    "Externo (unidad): detectadas": [abl.loc["Modelo completo (TF-IDF + indicadores)", "ext_detectadas"],
                                     abl.loc["Modelo completo + combinación (herramienta)", "ext_detectadas"]],
    "Externo (unidad): falsas alarmas": [abl.loc["Modelo completo (TF-IDF + indicadores)", "ext_falsas_alarmas"],
                                         abl.loc["Modelo completo + combinación (herramienta)", "ext_falsas_alarmas"]],
}, index=["Modelo base", "Modelo base + combinación"])
efecto.round(3)

# %% [markdown]
# La combinación sacrifica algo de F1 en la partición de prueba (casos de pruebas de reglas casi idénticos entre
# sí) a cambio de una mejora clara en aplicaciones reales, que es el uso previsto de la herramienta. Los
# resultados de la sección 5 ya corresponden a la herramienta con la combinación. Como los proyectos externos
# se habían usado antes en los diagnósticos, esas cifras deben leerse como una estimación algo optimista.

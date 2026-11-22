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

# %%
X = modelo.transformar(a_unidades(te))
p = modelo.probabilidad(X=X)
y = te.vulnerable.values
yp = (p >= modelo.umbral).astype(int)
m = metricas["detector"]["prueba"]
pd.Series({"Umbral": modelo.umbral, "Precisión": m["precision"], "Sensibilidad (recall)": m["recall"], "F1": m["f1"],
           "Exactitud": m["accuracy"], "AUC-ROC": m["roc_auc"], "Precisión promedio (AP)": m["ap"],
           "Tasa de falsos positivos": m["tasa_falsos_positivos"]}).round(3).to_frame("prueba")

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
juice, web = externa.get("juice_shop"), externa.get("fragmentos_web")
if web:
    filas["Fragmentos de foros y documentación"] = [web["f1"], web["roc_auc"]]
if juice:
    filas["OWASP Juice Shop (retos de código)"] = [juice["f1"], juice["roc_auc"]]
gen = pd.DataFrame(filas, index=["F1", "AUC-ROC"]).T.round(3)
gen

# %% [markdown]
# La diferencia entre los datos de ajuste y la prueba muestra el grado de sobreajuste. El modelo memoriza
# parte de los ejemplos de entrenamiento (como cualquier modelo léxico de alta dimensión), pero conserva
# un desempeño útil sobre proyectos y fuentes que nunca vio.

# %% [markdown]
# ## 5. Prueba funcional sobre proyectos de microservicios no vistos
#
# La herramienta completa (`vulnminer scan`) se ejecutó sobre cuatro proyectos vulnerables con
# vulnerabilidades documentadas (crAPI de OWASP, VAmPI, dvws-node y Damn Vulnerable RESTaurant) y sobre dos
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
pv = proy[proy.tipo == "vulnerable"]
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
# ### Fragmentos externos

# %%
filas = []
for nombre, mm in (("Fragmentos de foros y documentación", web), ("OWASP Juice Shop (retos de código)", juice)):
    if mm:
        filas.append({"conjunto": nombre, "n": mm["n"], "vulnerables": mm["vulnerables"], "precision": mm["precision"],
                      "recall": mm["recall"], "f1": mm["f1"], "accuracy": mm["accuracy"], "auc": mm["roc_auc"]})
pd.DataFrame(filas).round(3)

# %%
if web:
    w = pd.DataFrame(web["detalle"])
    w["acierto"] = w.vulnerable == w.prediccion
    display(w[["id", "tipo", "lenguaje", "vulnerable", "probabilidad", "prediccion", "acierto", "categorias", "owasp_esperado"]])

# %% [markdown]
# # Fase 1 · SAMPLE — Muestreo y selección de datos
#
# **Objetivo:** construir un conjunto de datos representativo con ejemplos de código fuente y de
# configuración, vulnerables y no vulnerables, asociados a las categorías **OWASP Top 10:2025** y
# **OWASP API Security Top 10:2023**.
#
# El dataset se construye con `scripts/construir_dataset.py`. Cada registro es una **unidad**: una
# función, un *handler* de una ruta o un bloque de configuración (un servicio de `docker-compose`, una
# sección de `application.yml`, una etapa de un `Dockerfile`, una ruta de OpenAPI). Uso exactamente el
# mismo segmentador que la herramienta CLI, de modo que el modelo aprende con el mismo tipo de
# fragmento que luego clasifica en un proyecto real.

# %%
import json
import sys
from pathlib import Path

import pandas as pd

BASE = Path.cwd().parent if Path.cwd().name == "notebooks" else Path.cwd()
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "notebooks"))
pd.set_option("display.max_colwidth", 80)
df = pd.read_csv(BASE / "datos" / "dataset.csv", keep_default_na=False)
print(f"{len(df):,} unidades etiquetadas | {df.vulnerable.sum():,} vulnerables | {(df.vulnerable == 0).sum():,} no vulnerables")

# %% [markdown]
# ## 1. Fuentes de datos
#
# | Fuente | Qué aporta | Cómo se obtiene la etiqueta |
# |---|---|---|
# | **semgrep-rules** | Pruebas de reglas de seguridad (Java, Python, JS, TS, Dockerfile, docker-compose) | Línea anotada `ruleid:` (vulnerable) u `ok:` (seguro); CWE en los metadatos de la regla |
# | **CodeQL** (GitHub) | Pruebas de consultas de seguridad | Comentarios `$ Alert`, `BAD`, `NOT OK` / `GOOD`, `OK`; CWE en el nombre del directorio |
# | **OWASP Benchmark** Java v1.2 y Python v0.1 | Casos de prueba con resultado esperado (fuente sugerida en el enunciado) | Archivo `expectedresults` (verdadero/falso) y su CWE |
# | **KICS** (Checkmarx) | Pruebas positivas y negativas de Dockerfile, docker-compose y OpenAPI | Línea esperada de la prueba positiva; consultas de seguridad seleccionadas |
# | **SecurityEval** | Ejemplos Python inseguros clasificados por CWE | Etiqueta del conjunto |
# | **Casos controlados** | Pares vulnerable/corregido de API (BOLA, BFLA, asignación masiva, consumo de recursos, inventario...) en Express, NestJS, FastAPI, Flask y Spring Boot | Etiqueta por diseño (fuente sugerida en el enunciado) |
# | **Código benigno** | 25 proyectos reales (boilerplates de NestJS/Express, Spring Boot, FastAPI, Flask, Django...) | Código de producción sin vulnerabilidades conocidas |
#
# La versión exacta (commit) de cada repositorio queda registrada en `datos/versiones_fuentes.json`.

# %%
versiones = json.loads((BASE / "datos" / "versiones_fuentes.json").read_text())
pd.DataFrame([{"nombre": k, "repositorio": v["repositorio"], "commit": v["commit"][:10], "uso": v["uso"]}
              for k, v in versiones.items()]).sort_values(["uso", "nombre"]).reset_index(drop=True)

# %%
tabla = (df.groupby("fuente").agg(unidades=("id", "size"), vulnerables=("vulnerable", "sum"),
                                  proyectos=("proyecto", "nunique"))
         .assign(no_vulnerables=lambda t: t.unidades - t.vulnerables)
         .sort_values("unidades", ascending=False))
tabla.loc["Total"] = tabla.sum()
tabla

# %% [markdown]
# ## 2. Diccionario de datos

# %%
pd.read_csv(BASE / "datos" / "diccionario_datos.csv")

# %% [markdown]
# Ejemplo de un registro (una unidad vulnerable de un caso controlado):

# %%
ejemplo = df[(df.fuente == "casos-controlados") & (df.api2023.str.contains("API1"))].iloc[0]
print(ejemplo[["fuente", "archivo", "lenguaje", "unidad", "cwe", "owasp2025", "api2023", "origen_etiqueta"]].to_string())
print("\n" + ejemplo.codigo)

# %% [markdown]
# ## 3. Correspondencia CWE – OWASP
#
# La tabla se genera con `scripts/construir_mapeo_cwe.py` a partir de los **documentos oficiales**:
# la sección *List of Mapped CWEs* de cada categoría del OWASP Top 10:2025 y las referencias externas
# de cada riesgo del OWASP API Security Top 10:2023. Algunos CWE no figuran en las listas oficiales,
# pero su CWE padre en la jerarquía de MITRE sí (por ejemplo, CWE-943 *NoSQL Injection*, hijo de
# CWE-74). Esas relaciones se marcan como **extendidas** y llevan su justificación.

# %%
corr = pd.read_csv(BASE / "datos" / "correspondencias_cwe_owasp.csv", keep_default_na=False)
print(f"{len(corr)} CWE en la tabla | Top 10 oficial: {(corr.tipo_top10 == 'oficial').sum()} | "
      f"Top 10 extendida: {(corr.tipo_top10 == 'extendida').sum()} | con categoría API: {(corr.owasp_api_2023 != '').sum()}")
corr[corr.owasp_api_2023 != ""][["cwe", "nombre", "owasp_top10_2025", "owasp_api_2023", "tipo_api"]]

# %% [markdown]
# ## 4. Justificación del procedimiento de muestreo
#
# - **Unidades de análisis realistas.** Se etiqueta la función o bloque completo que contiene la línea
#   anotada, con el mismo segmentador que usa la herramienta.
# - **Pares vulnerable/corregido.** Semgrep, CodeQL, KICS y los casos controlados aportan versiones
#   corregidas casi idénticas a las vulnerables: obligan al modelo a fijarse en la diferencia relevante
#   (parámetros enlazados, verificación del propietario, rol, límites...) y no en palabras sueltas.
# - **Código normal de proyectos reales.** Sin él, el modelo marcaría cualquier código que no se parezca
#   a un ejemplo de libro. Se tomaron hasta 600 unidades por proyecto de 25 proyectos y se excluyeron las
#   carpetas de ejemplos y pruebas, que a menudo contienen código inseguro a propósito.
# - **Control de fugas de etiqueta.** Se eliminan los comentarios que delatan la clase (`ruleid`, `BAD`,
#   `vulnerable`...) y se neutralizan los identificadores como `bad1()` o `BenchmarkTest00042`.
# - **Balance.** Como máximo 12 unidades por archivo y 420 por CWE y fuente, para que ningún origen domine.
# - **Limpieza.** Se descartan duplicados, unidades con etiquetas contradictorias y vulnerabilidades sin
#   categoría OWASP (p. ej. seguridad de memoria).

# %% [markdown]
# ## 5. Partición entrenamiento / validación / prueba (70/15/15)
#
# La partición se hace **por grupo de origen**: todas las unidades de un mismo proyecto, del mismo
# directorio de pruebas de una regla o de la misma familia de casos controlados (framework + estilo)
# quedan en la misma partición. Así ninguna partición comparte procedencia con otra y la prueba mide la
# generalización a proyectos y estilos no vistos. Los grupos se asignan con **estratificación iterativa
# multietiqueta** (Sechidis et al., 2011), de modo que cada categoría OWASP aparezca en las tres particiones.

# %%
part = (df.groupby("particion").agg(unidades=("id", "size"), vulnerables=("vulnerable", "sum"),
                                    grupos=("proyecto", "nunique"))
        .reindex(["entrenamiento", "validacion", "prueba"]))
part["porcentaje"] = (100 * part.unidades / part.unidades.sum()).round(1)
part

# %%
# Comprobación: ningún grupo de origen ni ningún fragmento de código aparece en dos particiones
from vulnminer.lexico import limpiar_codigo
import re

assert (df.groupby("proyecto").particion.nunique() == 1).all()
norm = df.codigo.map(lambda c: re.sub(r"\s+", " ", limpiar_codigo(c)).strip())
assert norm.is_unique
print("Sin fugas entre particiones: OK")

# %%
vul = df[df.vulnerable == 1]
filas = []
for col in ("owasp2025", "api2023"):
    e = vul.assign(c=vul[col].str.split(";")).explode("c").reset_index(drop=True)
    filas.append(pd.crosstab(e[e.c != ""].c, e[e.c != ""].particion))
cobertura = pd.concat(filas)[["entrenamiento", "validacion", "prueba"]]
cobertura

# %% [markdown]
# **Conclusión de la fase.** El dataset tiene muchos más registros que el mínimo exigido (500, con 100 o
# más no vulnerables), proviene de fuentes públicas trazables más casos controlados propios, cubre los
# cuatro lenguajes del alcance y los archivos de configuración, y está dividido sin fugas entre particiones.
# La categoría **API6:2023** (flujos de negocio sensibles) no tiene ejemplos, porque depende de la lógica
# de negocio de cada aplicación, y **API9:2023** tiene muy pocos: ambas se tratan en las fases siguientes.

# %% [markdown]
# # Fase 3 · MODIFY — Preparación y transformación de los datos
#
# **Objetivo:** transformar cada unidad de código o configuración en una representación numérica adecuada
# para los algoritmos de clasificación, sin filtrar información entre particiones.
#
# El pipeline completo está en `vulnminer/modelo.py` (función `representacion`) y es el mismo que usa la
# herramienta al analizar un proyecto: se serializa junto con el modelo.

# %%
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

BASE = Path.cwd().parent if Path.cwd().name == "notebooks" else Path.cwd()
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "notebooks"))
import estilo as E  # noqa: E402
from vulnminer import caracteristicas as C  # noqa: E402
from vulnminer.lexico import limpiar_codigo, neutralizar_identificadores, preparar, tokenizar  # noqa: E402
from vulnminer.modelo import a_unidades, representacion  # noqa: E402
from vulnminer.segmentacion import segmentar  # noqa: E402

E.aplicar()
df = pd.read_csv(BASE / "datos" / "dataset.csv", keep_default_na=False)

# %% [markdown]
# ## 1. Limpieza de registros
#
# Realizada en `scripts/construir_dataset.py` (fase Sample) y verificada en la fase Explore:
# duplicados exactos, etiquetas contradictorias, unidades vacías y vulnerabilidades sin categoría OWASP se
# eliminan; las etiquetas se normalizan a los identificadores oficiales (`A05:2025`, `API1:2023`, `CWE-89`).

# %% [markdown]
# ## 2. Segmentación en unidades
#
# Un archivo se divide en funciones, *handlers* o bloques de configuración. Ejemplo con un controlador
# NestJS: cada método conserva sus decoradores y recibe como **contexto** la cabecera de la clase (los
# `@UseGuards` declarados a nivel de clase protegen todos los métodos).

# %%
codigo = """@Controller('orders')
@UseGuards(JwtAuthGuard)
export class OrdersController {
  constructor(private readonly orders: OrdersService) {}

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.orders.findById(id);
  }

  @Delete(':id')
  @Roles('admin')
  remove(@Param('id') id: string) {
    return this.orders.remove(id);
  }
}
"""
for u in segmentar("orders.controller.ts", codigo):
    print(f"--- {u.nombre} (líneas {u.linea_inicio}-{u.linea_fin}) | contexto: {u.contexto.splitlines()[:2]}")
    print(u.texto)

# %% [markdown]
# ## 3. Limpieza anti-fuga y normalización
#
# Las pruebas de reglas marcan sus ejemplos con comentarios (`// ruleid:`, `# BAD`, `// $ Alert`) y nombran
# las funciones `bad1()`, `goodG2B()`... Si se conservan, el modelo aprende las marcas y no el código. Se
# eliminan los comentarios que delatan la etiqueta y se neutralizan esos identificadores; las APIs reales
# como `yaml.safe_load` o `secure_filename` se respetan.

# %%
ejemplo = """def bad_query(request):
    # ruleid: tainted-sql-string
    q = request.args.get("q")
    cursor.execute("SELECT * FROM t WHERE name = '" + q + "'")  # BAD
    data = yaml.safe_load(texto)  # calcula la configuración
"""
print(preparar(ejemplo))

# %% [markdown]
# ## 4. Tokenización del código
#
# Tokens propios de un lenguaje de programación: identificadores, operadores y marcadores de interpolación
# (`+`, `${`, `%`), más los sub-tokens de los identificadores compuestos (`userId` → `user`, `id`).

# %%
print(tokenizar("db.query(`SELECT * FROM users WHERE id = ${req.params.userId}`)"))

# %% [markdown]
# ## 5. Representación numérica (tres bloques)
#
# | Bloque | Técnica | Qué capta |
# |---|---|---|
# | Tokens | TF-IDF de unigramas y bigramas de tokens (60 000 términos, *sublinear tf*) | Vocabulario y APIs usadas (`findById`, `verify`, `shell=True`) |
# | Caracteres | TF-IDF de n-gramas de 3 a 5 caracteres (60 000) | Diferencias finas como `execute(sql + x)` frente a `execute(sql, (x,))` |
# | Seguridad | 151 características del análisis estático, escaladas a [−1, 1] | Fuentes de entrada, consultas dinámicas, guards, roles, propiedad, criptografía, errores, configuración, endpoints y dependencias, más **interacciones** (entrada → operación peligrosa) y métricas de código |
#
# El vocabulario TF-IDF y el escalado se ajustan **solo con la partición de entrenamiento** y después se
# aplican a validación y prueba, para no filtrar información.

# %%
tr = df[df.particion == "entrenamiento"]
va = df[df.particion == "validacion"]
R = representacion().fit(a_unidades(tr))
Xtr = R.transform(a_unidades(tr))
bloques = {n: t.transform(a_unidades(tr.head(1))).shape[1] for n, t in R.transformer_list}
print("Dimensión de cada bloque:", bloques)
print(f"Matriz de características (entrenamiento): {Xtr.shape[0]:,} × {Xtr.shape[1]:,} | "
      f"densidad {Xtr.nnz / (Xtr.shape[0] * Xtr.shape[1]) * 100:.3f} %")

# %% [markdown]
# ### Características de seguridad sugeridas por el enunciado y su implementación

# %%
familias = pd.DataFrame([{"indicador": i.nombre, "familia": i.familia, "descripcion": i.descripcion} for i in C.INDICADORES])
correspondencia = {
    "bd": "Consultas dinámicas a bases de datos", "auth": "Autenticación y autorización",
    "validacion": "Validación de parámetros de entrada", "cripto": "Funciones criptográficas",
    "errores": "Gestión de errores y excepciones", "config": "Configuraciones de permisos y seguridad",
    "credenciales": "Gestión de tokens y credenciales", "rutas": "Rutas y endpoints REST",
    "externo": "Dependencias y componentes externos", "entrada": "Entradas no confiables",
    "inyeccion": "Operaciones peligrosas (sumideros)", "datos": "Propiedades y datos sensibles",
    "recursos": "Consumo de recursos",
}
resumen = familias.groupby("familia").indicador.apply(list).to_frame("indicadores")
resumen.insert(0, "caracteristica_sugerida", resumen.index.map(correspondencia))
resumen["n"] = resumen.indicadores.map(len)
resumen.sort_values("n", ascending=False)

# %%
print("Interacciones derivadas:", ", ".join(C.NOMBRES_DERIVADAS))
print("Métricas de código:", ", ".join(C.NOMBRES_METRICAS))

# %% [markdown]
# ### Ejemplo: vector de seguridad de una unidad BOLA y de su versión corregida

# %%
from vulnminer.segmentacion import Unidad  # noqa: E402

vulnerable = """@app.get('/orders/<int:order_id>')
@jwt_required()
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    return jsonify(order.to_dict())"""
corregida = """@app.get('/orders/<int:order_id>')
@jwt_required()
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != get_jwt_identity():
        abort(403)
    return jsonify(order.to_dict())"""
nombres = C.nombres_caracteristicas()
filas = {}
for etiqueta, texto in (("vulnerable", vulnerable), ("corregida", corregida)):
    v = C.vector(Unidad("a.py", "python", "codigo", "get_order", [], texto))
    filas[etiqueta] = pd.Series(v, index=nombres)
comp = pd.DataFrame(filas)
comp[(comp.vulnerable != comp.corregida) | ((comp.vulnerable > 0) & ~comp.index.str.startswith(("m_", "sub_", "len_")))].round(2)

# %% [markdown]
# La única diferencia relevante es la **verificación del propietario**, que activa el indicador
# `verificacion_propiedad` y desactiva la interacción `x_id_ruta_sin_propiedad`. El modelo aprende el peso
# de estas variables a partir de los datos: no hay una regla que asigne API1 directamente.

# %% [markdown]
# ## 6. Tratamiento del desbalance
#
# - **Entre clases** (≈ 2:1): pesos de clase balanceados (`class_weight="balanced"`) en todos los
#   algoritmos y umbral de decisión calibrado en validación (fase Model).
# - **Entre categorías:** clasificador uno-contra-el-resto con pesos balanceados por categoría, umbral propio
#   por categoría y un mínimo de 15 ejemplos de entrenamiento para considerar evaluable una categoría.
# - No uso sobremuestreo sintético (SMOTE): generar vectores TF-IDF interpolados no produce código
#   plausible, y los casos controlados ya aportan ejemplos reales de las categorías escasas.

# %%
pesos = len(tr) / (2 * tr.vulnerable.value_counts())
print("Pesos de clase en entrenamiento:", pesos.round(3).to_dict())

# %% [markdown]
# ## 7. Independencia de los conjuntos
#
# La matriz de validación y la de prueba se obtienen con `transform` (sin reajustar el vocabulario). Los
# términos que solo aparecen en validación no existen en la representación: es la misma situación que
# enfrenta la herramienta con un proyecto nuevo.

# %%
Xva = R.transform(a_unidades(va))
vocab_tok = R.transformer_list[0][1].named_steps["tfidf"].vocabulary_
cobertura = np.mean([(Xva[i].nnz > 0) for i in range(Xva.shape[0])])
print(f"Validación: {Xva.shape[0]:,} unidades transformadas con el vocabulario de entrenamiento "
      f"({len(vocab_tok):,} términos de tokens); {cobertura * 100:.1f} % con al menos un término conocido.")

# %% [markdown]
# **Conclusión de la fase.** Cada unidad se representa con ≈ 120 000 variables dispersas (TF-IDF de tokens y
# de caracteres) más 151 características de seguridad interpretables. El pipeline se ajusta solo con
# entrenamiento, es reproducible y se serializa con el modelo, de modo que la CLI aplica exactamente la
# misma transformación sin volver a entrenar.

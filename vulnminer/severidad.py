"""Estimación de la severidad y del estado de verificación de cada hallazgo.

La severidad NO se deriva de la confianza del modelo (sección 8.3.2 del enunciado):
- se parte de la severidad base del CWE (base de conocimiento) o de la categoría;
- se ajusta según el contexto: exposición a datos de la petición, endpoint público,
  archivo de pruebas/ejemplo, configuración de desarrollo.
Cada ajuste queda registrado en la justificación.
"""

import re

from .catalogo import REQUIEREN_REVISION_MANUAL, conocimiento

NIVELES = ["Baja", "Media", "Alta", "Crítica"]
SEVERIDAD_CATEGORIA = {
    "A01:2025": "Alta", "A02:2025": "Media", "A03:2025": "Media", "A04:2025": "Media", "A05:2025": "Alta",
    "A06:2025": "Media", "A07:2025": "Alta", "A08:2025": "Alta", "A09:2025": "Baja", "A10:2025": "Media",
    "API1:2023": "Alta", "API2:2023": "Alta", "API3:2023": "Media", "API4:2023": "Media", "API5:2023": "Alta",
    "API6:2023": "Media", "API7:2023": "Alta", "API8:2023": "Media", "API9:2023": "Baja", "API10:2023": "Media",
}
RUTA_NO_PRODUCTIVA = re.compile(r"(^|/)(tests?|examples?|samples?|demo|mocks?|fixtures|scripts|docs?)(/|$)|"
                                r"(\.|-|_)(dev|local|test|example)\.(ya?ml|properties|env|json)$", re.I)
SENSIBLES = {"x_entrada_sql", "x_entrada_comando", "x_entrada_eval", "x_entrada_deserializacion", "x_entrada_peticion_sin_lista",
             "x_entrada_archivo_sin_normalizar", "x_entrada_nosql", "x_entrada_xml"}


def estimar(cwe, categorias, unidad, indicadores_activos):
    """Devuelve (nivel, justificación)."""
    motivos = []
    base = None
    info = conocimiento(cwe) if cwe else None
    if info:
        base = info[2]
        motivos.append(f"severidad base de {cwe}: {base}")
    elif categorias:
        base = max((SEVERIDAD_CATEGORIA.get(c, "Media") for c in categorias), key=NIVELES.index)
        motivos.append(f"severidad base de la categoría {categorias[0]}: {base}")
    else:
        base = "Media"
        motivos.append("sin categoría determinada: severidad media por defecto")
    nivel = NIVELES.index(base)

    if indicadores_activos & SENSIBLES:
        if nivel < 3:
            nivel += 1
        motivos.append("datos de la petición llegan a una operación peligrosa en la misma función")
    elif "entrada_http" in indicadores_activos and "ruta_definida" in indicadores_activos and nivel <= 1:
        nivel += 1
        motivos.append("expuesto en un endpoint que recibe datos del cliente")

    if "x_ruta_sin_autenticacion" in indicadores_activos and any(c in ("A01:2025", "API1:2023", "API5:2023") for c in categorias):
        if nivel < 3:
            nivel += 1
        motivos.append("el endpoint no muestra un mecanismo de autenticación")

    if RUTA_NO_PRODUCTIVA.search(unidad.archivo.replace("\\", "/")):
        nivel = max(nivel - 1, 0)
        motivos.append("el archivo parece de pruebas, ejemplos o desarrollo")

    return NIVELES[nivel], "; ".join(motivos) + "."


def estado(categorias, indicadores_activos, tiene_categoria):
    """Estado de verificación: los hallazgos son siempre potenciales (análisis estático)."""
    if not tiene_categoria:
        return "Pendiente de revisión (categoría no determinada)"
    if any(c in REQUIEREN_REVISION_MANUAL for c in categorias):
        return "Potencial - requiere verificación manual o dinámica"
    if any(i.startswith("x_") for i in indicadores_activos):
        return "Potencial - respaldado por evidencia estática"
    return "Potencial - requiere verificación"

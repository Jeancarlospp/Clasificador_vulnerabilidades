"""Análisis de un proyecto de microservicios con el modelo entrenado (proceso de la sección 8.3).

1. Identifica la raíz del proyecto y descubre los microservicios y sus tecnologías.
2. Selecciona los archivos de código y configuración soportados.
3. Divide cada archivo en unidades (funciones, handlers, bloques de configuración).
4-6. Extrae características, aplica el pipeline y obtiene las predicciones del modelo.
7. Asigna las categorías OWASP Top 10:2025 / API Security Top 10:2023 predichas.
8. Localiza la línea más relevante (oclusión) y reúne la evidencia.
"""

import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from . import __version__
from . import caracteristicas as C
from .catalogo import (API2023, DESCRIPCION_CATEGORIA, DESCRIPCION_PATRON, OWASP2025, RECOMENDACION_CATEGORIA,
                       conocimiento, nombre_categoria, nombre_cwe)
from .descubrimiento import descubrir, es_generado, leer_texto, marcar_frontend, resumen_servicio
from .modelo import NOMBRES_ALGORITMO
from .segmentacion import segmentar
from .severidad import NIVELES, estado, estimar

RUTA_MODELO = Path(__file__).with_name("modelos") / "vulnminer.joblib"


@dataclass
class Hallazgo:
    id: str
    microservicio: str
    archivo: str
    linea: int
    linea_inicio: int
    linea_fin: int
    unidad: str
    lenguaje: str
    descripcion: str
    evidencia: dict
    owasp_top10: list
    owasp_api: list
    cwe: dict
    confianza: float
    severidad: str
    justificacion_severidad: str
    recomendacion: str
    estado: str
    categoria_sugerida: dict = field(default_factory=dict)


def cargar_modelo(ruta=None):
    from .modelo import ModeloVulnminer

    ruta = Path(ruta) if ruta else RUTA_MODELO
    if not ruta.exists():
        raise FileNotFoundError(f"No se encontró el modelo entrenado en {ruta}. Ejecute scripts/entrenar.py")
    return ModeloVulnminer.cargar(ruta)


def _fragmento(lineas_archivo, linea, contexto=2):
    ini = max(linea - 1 - contexto, 0)
    fin = min(linea + contexto, len(lineas_archivo))
    return [{"linea": i + 1, "codigo": lineas_archivo[i], "resaltada": i + 1 == linea} for i in range(ini, fin)]


def _descripcion(cwe, categorias, unidad, activos=()):
    info = conocimiento(cwe) if cwe else None
    base = info[0] if info else (DESCRIPCION_CATEGORIA[categorias[0]] if categorias else
                                 "Código o configuración similar a ejemplos vulnerables; la categoría no pudo determinarse.")
    patrones = [DESCRIPCION_PATRON[a] for a in sorted(activos) if a in DESCRIPCION_PATRON]
    if patrones:
        base = base.rstrip(".") + ". Evidencia: " + "; ".join(patrones[:2]) + "."
    return base


def _recomendacion(cwe, categorias):
    info = conocimiento(cwe) if cwe else None
    if info:
        return info[1]
    if categorias:
        return RECOMENDACION_CATEGORIA[categorias[0]]
    return "Revisar manualmente el fragmento: el modelo detectó similitud con código vulnerable pero no pudo determinar la categoría."


def _cwe_coherente(cwe, categorias, catalogo_cwe):
    """El CWE predicho se informa solo si es coherente con alguna categoría asignada."""
    from .catalogo import cwe_a_api2023, cwe_a_owasp2025

    if not cwe:
        return None
    if not categorias:
        return cwe
    propias = {cwe_a_owasp2025(cwe)} | set(cwe_a_api2023(cwe, True))
    return cwe if propias & set(categorias) else None


def analizar_unidades(modelo, unidades, estandares=("owasp2025", "api2023"), umbral=None, localizar=True):
    """Predicción y armado de la información de cada unidad detectada como vulnerable."""
    preds = modelo.predecir(unidades, umbral)
    resultados = []
    for u, p in zip(unidades, preds):
        if not p["vulnerable"]:
            continue
        t10 = [c for c in p["owasp2025"]] if "owasp2025" in estandares else []
        api = [c for c in p["api2023"]] if "api2023" in estandares else []
        categorias = [c for c, _ in t10 + api]
        cwe = _cwe_coherente(p["cwe"], categorias, None)
        vec = dict(zip(C.nombres_caracteristicas(), C.vector(u)))
        activos = {n for n, v in vec.items() if v > 0 and not n.startswith(("m_", "sub_", "len_", "ctx_"))}
        evid = C.evidencias(u)
        lineas_rel = modelo.lineas_relevantes(u, max_lineas=6) if localizar else []
        lineas_ind = {l for _, l, _ in evid}
        lineas_op = {l for n, l, _ in evid if C.FAMILIA[n] not in C.FAMILIAS_CONTEXTO}
        # Línea reportada: entre las que más influyen en la predicción (oclusión), se prefiere la que contiene
        # la operación peligrosa (consulta, deserialización, petición saliente...) antes que la fuente de entrada.
        positivas = [l for l, caida in lineas_rel if caida > 0]
        linea = (next((l for l in positivas if l in lineas_op), None)
                 or next((l for _, l, _ in evid if l in lineas_op and l in {x for x, _ in lineas_rel}), None)
                 or next((l for l in positivas if l in lineas_ind), None)
                 or (positivas[0] if positivas else None)
                 or (min(lineas_op) if lineas_op else None)
                 or (evid[0][1] if evid else u.linea_inicio))
        lineas_rel = lineas_rel[:3]
        resultados.append({"unidad": u, "prediccion": p, "t10": t10, "api": api, "categorias": categorias, "cwe": cwe,
                           "activos": activos, "evidencias": evid, "lineas_relevantes": lineas_rel, "linea": linea})
    return resultados


def analizar_proyecto(raiz, modelo=None, estandares=("owasp2025", "api2023"), umbral=None, incluir_pruebas=False,
                      progreso=None):
    t0 = time.time()
    raiz = Path(raiz).resolve()
    modelo = modelo or cargar_modelo()
    servicios, total = descubrir(raiz, incluir_pruebas)
    unidades, origen, textos = [], [], {}
    for s in servicios:
        for rel in s.archivos:
            texto, motivo = leer_texto(raiz / rel)
            if texto is None:
                s.omitidos[motivo] = s.omitidos.get(motivo, 0) + 1
                continue
            if es_generado(rel, texto):
                continue
            textos[rel] = texto.replace("\r\n", "\n").replace("\t", "    ").splitlines()
            for u in marcar_frontend(segmentar(rel, texto), s, rel):
                unidades.append(u)
                origen.append(s)
    if progreso:
        progreso(f"{len(servicios)} microservicios, {total} archivos, {len(unidades)} unidades de análisis")

    detectados = []
    lote = 1500
    for k in range(0, len(unidades), lote):
        detectados.extend(analizar_unidades(modelo, unidades[k:k + lote], estandares, umbral))
    por_unidad = {id(d["unidad"]): d for d in detectados}

    # Fusiona ventanas de una misma función que apuntan a la misma línea
    vistos = {}
    hallazgos = []
    for u, s in zip(unidades, origen):
        d = por_unidad.get(id(u))
        if d is None:
            continue
        clave = (u.archivo, d["linea"])
        if clave in vistos:
            previo = vistos[clave]
            if d["prediccion"]["probabilidad"] <= previo.confianza:
                continue
            hallazgos.remove(previo)
        p = d["prediccion"]
        cwe = d["cwe"]
        sev, just = estimar(cwe, d["categorias"], u, d["activos"])
        indicadores = [{"indicador": n, "descripcion": C.DESCRIPCION[n], "linea": l, "codigo": t[:200]} for n, l, t in d["evidencias"]
                       if n in d["activos"] or n.startswith("x_")]
        derivadas = sorted(a for a in d["activos"] if a.startswith("x_"))
        h = Hallazgo(
            id="", microservicio=s.nombre, archivo=u.archivo, linea=d["linea"], linea_inicio=u.linea_inicio,
            linea_fin=u.linea_fin, unidad=u.nombre, lenguaje=u.lenguaje,
            descripcion=_descripcion(cwe, d["categorias"], u, d["activos"]),
            evidencia={"fragmento": _fragmento(textos.get(u.archivo, []), d["linea"]),
                       "lineas_influyentes": [{"linea": l, "aporte": round(c, 3)} for l, c in d["lineas_relevantes"] if c > 0],
                       "indicadores": indicadores[:8], "patrones_combinados": derivadas,
                       "probabilidad_modelo_base": round(p["probabilidad_base"], 3),
                       "probabilidad_combinada": None if p["probabilidad_combinada"] is None
                       else round(p["probabilidad_combinada"], 3)},
            owasp_top10=[{"codigo": c, "nombre": nombre_categoria(c), "probabilidad": round(q, 3)} for c, q in d["t10"]],
            owasp_api=[{"codigo": c, "nombre": nombre_categoria(c), "probabilidad": round(q, 3)} for c, q in d["api"]],
            cwe={"id": cwe, "nombre": nombre_cwe(cwe)} if cwe else {},
            confianza=round(p["probabilidad"], 3), severidad=sev, justificacion_severidad=just,
            recomendacion=_recomendacion(cwe, d["categorias"]),
            estado=estado(d["categorias"], d["activos"], bool(d["categorias"])),
            categoria_sugerida={} if d["categorias"] else {"codigo": p["categoria_sugerida"][0],
                                                           "probabilidad": round(p["categoria_sugerida"][1], 3)},
        )
        vistos[clave] = h
        hallazgos.append(h)

    hallazgos.sort(key=lambda h: (-NIVELES.index(h.severidad), -h.confianza, h.microservicio, h.archivo, h.linea))
    for i, h in enumerate(hallazgos, 1):
        h.id = f"VM-{i:03d}"

    seleccion = [c for e in estandares for c in (OWASP2025 if e == "owasp2025" else API2023)]
    return {
        "herramienta": "vulnminer", "version": __version__, "fecha": datetime.now().isoformat(timespec="seconds"),
        "proyecto": raiz.name, "ruta": str(raiz), "estandares": list(estandares),
        "modelo": {"detector": NOMBRES_ALGORITMO.get(modelo.algoritmo_detector, modelo.algoritmo_detector),
                   "categorias": NOMBRES_ALGORITMO.get(modelo.algoritmo_categorias, modelo.algoritmo_categorias),
                   "umbral": umbral if umbral is not None else modelo.umbral,
                   "combinacion": ({"umbral_base_codigo": umbral if umbral is not None else modelo.umbral_base_codigo,
                                    "umbral_combinado": modelo.umbral_combinado} if modelo.combinador is not None else None),
                   **{k: v for k, v in modelo.metadatos.items()
                                                                               if k in ("version", "fecha", "detector_prueba")}},
        "resumen": {"microservicios": len([s for s in servicios if s.ruta != "."]) or len(servicios),
                    "archivos_analizados": total, "unidades_analizadas": len(unidades), "hallazgos": len(hallazgos),
                    "duracion_segundos": round(time.time() - t0, 1),
                    "archivos_omitidos": dict(sum((Counter(s.omitidos) for s in servicios), Counter())),
                    "archivos_no_soportados": dict(sum((Counter(s.no_soportados) for s in servicios), Counter()))},
        "microservicios": [resumen_servicio(s) for s in servicios],
        "hallazgos": [asdict(h) for h in hallazgos],
        "categorias": {c: {"nombre": nombre_categoria(c),
                           "estado": "no evaluada" if c in modelo.no_evaluadas or c not in modelo.categorias else "evaluada",
                           "motivo": modelo.no_evaluadas.get(c, "" if c in modelo.categorias else "sin clasificador entrenado")}
                       for c in seleccion},
    }

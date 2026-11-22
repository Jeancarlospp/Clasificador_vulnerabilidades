"""Descubrimiento de microservicios y de los archivos a analizar (RF06).

Un microservicio se reconoce por su directorio raíz, que contiene un manifiesto de
dependencias (package.json, pom.xml, build.gradle, requirements.txt, pyproject.toml...)
o un Dockerfile. Si existe un docker-compose, los nombres de sus servicios con ``build``
se usan para nombrar los directorios correspondientes.

Los archivos que no pertenecen a ningún servicio (p. ej. el docker-compose de la raíz o
la carpeta de despliegue) se agrupan en "(raíz del proyecto)".
"""

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .segmentacion import tipo_archivo

RAIZ_PROYECTO = "(raíz del proyecto)"
MANIFIESTOS = {"package.json", "pom.xml", "build.gradle", "build.gradle.kts", "requirements.txt", "pyproject.toml",
               "setup.py", "pipfile", "go.mod", "dockerfile"}
DIRECTORIOS_EXCLUIDOS = {"node_modules", ".git", "dist", "build", "target", "out", "coverage", "venv", ".venv", "env",
                         "__pycache__", ".idea", ".vscode", "vendor", ".next", ".nuxt", ".gradle", "bin", "obj",
                         ".mvn", ".pytest_cache", ".mypy_cache", "site-packages", "bower_components", "reportes",
                         ".angular", ".cache", "generated", "gen", "migrations", "alembic", "static", "assets"}
DIRECTORIOS_PRUEBA = {"test", "tests", "__tests__", "spec", "specs", "e2e", "testing", "fixtures", "mocks", "__mocks__"}
ARCHIVOS_PRUEBA = re.compile(r"(\.(spec|test|e2e-spec)\.(ts|js|tsx|jsx)$|^test_.*\.py$|_test\.py$|Tests?\.java$|IT\.java$|conftest\.py$)")
OTROS_EXCLUIDOS = re.compile(r"(\.min\.js$|\.d\.ts$|\.bundle\.js$|-lock\.json$|package-lock\.json$|\.map$|"
                             r"swagger-ui|polyfills?\.(js|ts)$)")
TAMANO_MAXIMO = 1_000_000
GENERICOS = {"src", "app", "server", "backend", "api", "service", "main", "code", "source"}

FRAMEWORKS = [
    ("NestJS", "package.json", r"\"@nestjs/core\""),
    ("Express", "package.json", r"\"express\""),
    ("Fastify", "package.json", r"\"fastify\""),
    ("Koa", "package.json", r"\"koa\""),
    ("Next.js", "package.json", r"\"next\""),
    ("React", "package.json", r"\"react\""),
    ("Angular", "package.json", r"\"@angular/core\""),
    ("Spring Boot", "pom.xml", r"spring-boot"),
    ("Spring Boot", "build.gradle", r"spring-boot|org\.springframework\.boot"),
    ("Spring Boot", "build.gradle.kts", r"spring-boot|org\.springframework\.boot"),
    ("Quarkus", "pom.xml", r"io\.quarkus"),
    ("Micronaut", "pom.xml", r"io\.micronaut"),
    ("FastAPI", "requirements.txt", r"(?im)^fastapi"),
    ("FastAPI", "pyproject.toml", r"(?i)fastapi"),
    ("Flask", "requirements.txt", r"(?im)^flask"),
    ("Flask", "pyproject.toml", r"(?i)\bflask\b"),
    ("Django", "requirements.txt", r"(?im)^django"),
    ("Django", "pyproject.toml", r"(?i)\bdjango\b"),
    ("Go", "go.mod", r"module "),
]
NOMBRE_LENGUAJE = {"java": "Java", "python": "Python", "javascript": "JavaScript", "typescript": "TypeScript",
                   "kotlin": "Kotlin", "config": "Configuración"}


@dataclass
class Servicio:
    nombre: str
    ruta: str                     # relativa a la raíz del proyecto ("." para la raíz)
    tecnologias: list = field(default_factory=list)
    lenguajes: dict = field(default_factory=dict)
    archivos: list = field(default_factory=list)    # rutas relativas a la raíz del proyecto
    no_soportados: dict = field(default_factory=dict)


def _recorrer(raiz, incluir_pruebas):
    for actual, dirs, archivos in os.walk(raiz):
        dirs[:] = sorted(d for d in dirs if d.lower() not in DIRECTORIOS_EXCLUIDOS and not d.startswith(".")
                         and (incluir_pruebas or d.lower() not in DIRECTORIOS_PRUEBA))
        rel_dir = Path(actual).relative_to(raiz)
        if not incluir_pruebas and len(rel_dir.parts) >= 2 and rel_dir.parts[-2:] == ("src", "test"):
            dirs[:] = []
            continue
        if not incluir_pruebas and "src/test" in str(rel_dir).replace(os.sep, "/"):
            continue
        yield Path(actual), sorted(archivos)


def _servicios_compose(raiz):
    """{directorio_relativo: nombre_servicio} a partir de los docker-compose del proyecto."""
    nombres = {}
    for archivo in list(raiz.glob("*compose*.y*ml")) + list(raiz.glob("*/*compose*.y*ml")):
        try:
            doc = yaml.safe_load(archivo.read_text(encoding="utf-8", errors="ignore")) or {}
        except yaml.YAMLError:
            continue
        for nombre, spec in (doc.get("services") or {}).items():
            build = (spec or {}).get("build") if isinstance(spec, dict) else None
            contexto = build if isinstance(build, str) else (build or {}).get("context") if isinstance(build, dict) else None
            if contexto:
                directorio = (archivo.parent / contexto).resolve()
                try:
                    nombres[str(directorio.relative_to(raiz.resolve()))] = nombre
                except ValueError:
                    pass
    return nombres


def _tecnologias(directorio):
    encontradas = []
    for nombre, manifiesto, patron in FRAMEWORKS:
        p = directorio / manifiesto
        if p.exists():
            try:
                if re.search(patron, p.read_text(encoding="utf-8", errors="ignore")) and nombre not in encontradas:
                    encontradas.append(nombre)
            except OSError:
                pass
    if "NestJS" in encontradas and "Express" in encontradas:
        encontradas.remove("Express")
    if (directorio / "Dockerfile").exists():
        encontradas.append("Docker")
    return encontradas


def descubrir(raiz, incluir_pruebas=False):
    """Devuelve (servicios, total_archivos_analizables). El primer servicio puede ser la raíz."""
    raiz = Path(raiz).resolve()
    candidatos = set()
    archivos = []
    for actual, nombres in _recorrer(raiz, incluir_pruebas):
        bajos = {n.lower() for n in nombres}
        if actual != raiz and (bajos & MANIFIESTOS):
            candidatos.add(actual)
        for n in nombres:
            if OTROS_EXCLUIDOS.search(n) or (not incluir_pruebas and ARCHIVOS_PRUEBA.search(n)):
                continue
            archivos.append(actual / n)

    # Un candidato anidado dentro de otro se considera parte del servicio externo, salvo que el
    # externo sea solo un agrupador (sin código propio fuera de los anidados).
    candidatos = sorted(candidatos, key=lambda p: len(p.parts))
    raices = []
    for c in candidatos:
        padre = next((r for r in raices if c.is_relative_to(r)), None)
        if padre is None:
            raices.append(c)
    raices = sorted(raices, key=lambda p: -len(p.parts))
    nombres_compose = _servicios_compose(raiz)

    servicios = {}
    for r in raices:
        rel = str(r.relative_to(raiz))
        nombre = nombres_compose.get(rel) or r.name
        if nombre.lower() in GENERICOS and r.parent != raiz:
            nombre = r.parent.name
        if any(s.nombre == nombre for s in servicios.values()):
            nombre = rel.replace(os.sep, "/")
        servicios[r] = Servicio(nombre=nombre, ruta=rel.replace(os.sep, "/"), tecnologias=_tecnologias(r))
    servicio_raiz = Servicio(nombre=RAIZ_PROYECTO if raices else raiz.name, ruta=".", tecnologias=_tecnologias(raiz))

    total = 0
    for archivo in archivos:
        try:
            if archivo.stat().st_size > TAMANO_MAXIMO:
                continue
        except OSError:
            continue
        rel = str(archivo.relative_to(raiz)).replace(os.sep, "/")
        dueno = next((servicios[r] for r in raices if archivo.is_relative_to(r)), servicio_raiz)
        t = tipo_archivo(archivo)
        if t is None:
            ext = archivo.suffix.lower()
            if ext in (".go", ".cs", ".php", ".rb", ".rs", ".scala", ".kt"):
                dueno.no_soportados[ext] = dueno.no_soportados.get(ext, 0) + 1
            continue
        dueno.archivos.append(rel)
        dueno.lenguajes[t[0]] = dueno.lenguajes.get(t[0], 0) + 1
        total += 1

    resultado = [s for s in servicios.values() if s.archivos or s.no_soportados]
    resultado.sort(key=lambda s: s.ruta)
    if servicio_raiz.archivos:
        resultado.insert(0, servicio_raiz)
    for s in resultado:
        s.lenguajes = dict(Counter(s.lenguajes).most_common())
        if not s.tecnologias:
            s.tecnologias = [NOMBRE_LENGUAJE.get(l, l) for l in s.lenguajes if l != "config"]
    return resultado, total


def resumen_servicio(s):
    return {"nombre": s.nombre, "ruta": s.ruta, "tecnologias": s.tecnologias,
            "lenguajes": {NOMBRE_LENGUAJE.get(k, k): v for k, v in s.lenguajes.items()},
            "archivos_analizados": len(s.archivos),
            "archivos_no_soportados": s.no_soportados}


def a_json(servicios):
    return json.dumps([resumen_servicio(s) for s in servicios], indent=2, ensure_ascii=False)

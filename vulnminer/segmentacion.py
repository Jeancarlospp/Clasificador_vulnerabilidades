"""Segmentación de archivos en unidades de análisis.

Una *unidad* es la porción de un archivo que el modelo clasifica:

- Código (Java, Python, JavaScript, TypeScript): cada función, método o *handler* de ruta,
  incluyendo sus anotaciones/decoradores y la llamada que registra la ruta
  (``router.get('/x', auth, (req, res) => {...})``). El código fuera de funciones se agrupa
  en bloques. Las unidades muy largas se dividen en ventanas que conservan la cabecera.
- Configuración: un servicio de ``docker-compose``, una sección de ``application.yml``,
  un grupo de propiedades, una etapa de un ``Dockerfile``, una ruta de una especificación
  OpenAPI o la sección de dependencias de un manifiesto.

El mismo segmentador se usa para construir el dataset y para analizar proyectos, de modo que
el modelo se entrena con el mismo tipo de unidad que luego clasifica.
"""

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

MAX_LINEAS = 60          # unidades más largas se dividen en ventanas
VENTANA, SOLAPE = 40, 10

EXT_LENGUAJE = {".py": "python", ".java": "java", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
                ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript", ".kt": "kotlin"}


@dataclass
class Unidad:
    archivo: str
    lenguaje: str            # java | python | javascript | typescript | config
    subtipo: str             # codigo | dockerfile | compose | yaml | properties | openapi | manifiesto | env
    nombre: str
    lineas: list             # números de línea (1-based) de cada línea de `texto`
    texto: str
    contexto: str = ""       # cabecera de clase / middleware del archivo (no se clasifica, da contexto)
    meta: dict = field(default_factory=dict)

    @property
    def linea_inicio(self):
        return self.lineas[0] if self.lineas else 0

    @property
    def linea_fin(self):
        return self.lineas[-1] if self.lineas else 0

    @property
    def tipo(self):
        return "codigo" if self.subtipo == "codigo" else "configuracion"


# ---------------------------------------------------------------------------------------------
# Clasificación del archivo
# ---------------------------------------------------------------------------------------------
MANIFIESTOS = {"package.json", "pom.xml", "requirements.txt", "build.gradle", "build.gradle.kts", "pyproject.toml",
               "pipfile", "go.mod"}


def tipo_archivo(ruta, texto=None):
    """Devuelve (lenguaje, subtipo) o None si el archivo no se analiza."""
    p = Path(ruta)
    nombre = p.name.lower()
    ext = p.suffix.lower()
    if nombre == "dockerfile" or nombre.startswith("dockerfile.") or nombre.endswith(".dockerfile") or ext == ".dockerfile":
        return "config", "dockerfile"
    if nombre in MANIFIESTOS or (nombre.startswith("requirements") and ext == ".txt"):
        return "config", "manifiesto"
    if re.match(r"(docker-)?compose[\w.-]*\.ya?ml$", nombre):
        return "config", "compose"
    if ext == ".properties":
        return "config", "properties"
    if nombre == ".env" or nombre.startswith(".env.") or ext == ".env":
        return "config", "env"
    if ext in (".yml", ".yaml", ".json"):
        if texto is None:
            try:
                texto = p.read_text(encoding="utf-8", errors="ignore")[:4000]
            except OSError:
                return None
        cabecera = texto[:4000]
        if re.search(r"^\s*[\"']?(openapi|swagger)[\"']?\s*:", cabecera, re.M):
            return "config", "openapi"
        if ext == ".json":
            return None
        if re.match(r"(application|bootstrap)[\w-]*\.ya?ml$", nombre) or "config" in nombre or "settings" in nombre:
            return "config", "yaml"
        if re.search(r"^services\s*:", cabecera, re.M) and re.search(r"^\s+image\s*:|^\s+build\s*:", cabecera, re.M):
            return "config", "compose"
        return None
    if ext in EXT_LENGUAJE:
        return EXT_LENGUAJE[ext], "codigo"
    return None


# ---------------------------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------------------------
def _crear(archivo, lenguaje, subtipo, nombre, lineas_texto, inicio, fin, contexto="", cabecera=None, meta=None):
    """Crea una o varias unidades (ventanas) para las líneas [inicio, fin] (índices 0-based)."""
    idx = [i for i in range(inicio, fin + 1) if i < len(lineas_texto)]
    idx = [i for i in idx if lineas_texto[i].strip()]
    if not idx:
        return []
    unidades = []
    if len(idx) <= MAX_LINEAS:
        bloques = [idx]
    else:
        bloques = []
        paso = VENTANA - SOLAPE
        for k in range(0, len(idx), paso):
            trozo = idx[k:k + VENTANA]
            if len(trozo) < 5 and bloques:
                break
            if cabecera is not None and cabecera not in trozo:
                trozo = [cabecera] + trozo
            bloques.append(trozo)
            if k + VENTANA >= len(idx):
                break
    for parte, trozo in enumerate(bloques):
        texto = "\n".join(lineas_texto[i] for i in trozo)
        nom = nombre if len(bloques) == 1 else f"{nombre} (parte {parte + 1})"
        unidades.append(Unidad(archivo, lenguaje, subtipo, nom, [i + 1 for i in trozo], texto, contexto, dict(meta or {})))
    return unidades


def _bloques_sueltos(archivo, lenguaje, subtipo, lineas, cubiertas, contexto=""):
    """Agrupa las líneas no cubiertas por unidades en bloques separados por líneas en blanco."""
    unidades, actual = [], []
    trivial = re.compile(r"^\s*(import |from \S+ import|package |using |require\(|const \w+ = require|#|//|/\*|\*|@|export \{|\}|\)|;|$)")

    def cerrar():
        utiles = [i for i in actual if not trivial.match(lineas[i])]
        if len(utiles) >= 2 or any(re.search(r"\b(app|router|server)\.(use|get|post|put|delete|patch|listen|all)\b|"
                                              r"\b(CORS|cors|helmet|rateLimit|session|csrf)\b|=\s*['\"`].{4,}['\"`]", lineas[i])
                                    for i in utiles):
            unidades.extend(_crear(archivo, lenguaje, subtipo, "bloque de módulo", lineas, actual[0], actual[-1], contexto))

    for i, linea in enumerate(lineas):
        if i in cubiertas:
            if actual:
                cerrar()
                actual = []
            continue
        if not linea.strip():
            if len(actual) >= 25:
                cerrar()
                actual = []
            continue
        actual.append(i)
        if len(actual) >= 40:
            cerrar()
            actual = []
    if actual:
        cerrar()
    return unidades


# ---------------------------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------------------------
def _segmentar_python(archivo, texto):
    lineas = texto.splitlines()
    try:
        arbol = ast.parse(texto)
    except (SyntaxError, ValueError):
        return _segmentar_python_indentacion(archivo, lineas)
    unidades, cubiertas = [], set()
    contexto_mod = "\n".join(l for l in lineas if re.match(
        r"\s*(app|router|api)\s*=|.*\b(include_router|add_middleware|CORSMiddleware|Limiter|login_manager|before_request|"
        r"JWTManager|CSRFProtect|Talisman|SessionMiddleware|dependencies\s*=)", l))[:1500]

    def visitar(nodo, contexto_clase=""):
        for hijo in ast.iter_child_nodes(nodo):
            if isinstance(hijo, (ast.FunctionDef, ast.AsyncFunctionDef)):
                anidadas = [n for n in ast.walk(hijo) if n is not hijo and isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
                inicio = min([d.lineno for d in hijo.decorator_list] + [hijo.lineno]) - 1
                fin = hijo.end_lineno - 1
                if anidadas and (fin - inicio) > MAX_LINEAS:
                    visitar(hijo, contexto_clase)
                    continue
                unidades.extend(_crear(archivo, "python", "codigo", hijo.name, lineas, inicio, fin,
                                       (contexto_clase + "\n" + contexto_mod).strip(), cabecera=hijo.lineno - 1))
                cubiertas.update(range(inicio, fin + 1))
            elif isinstance(hijo, ast.ClassDef):
                inicio = min([d.lineno for d in hijo.decorator_list] + [hijo.lineno]) - 1
                cab = "\n".join(lineas[inicio:hijo.lineno])
                bases = " ".join(ast.unparse(b) for b in hijo.bases) if hasattr(ast, "unparse") else ""
                visitar(hijo, f"{cab} {bases}".strip())
                # Atributos de clase (p. ej. modelos/esquemas pydantic, serializadores): bloque propio
                cuerpo = [n for n in hijo.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
                if cuerpo:
                    ini_c, fin_c = cuerpo[0].lineno - 1, cuerpo[-1].end_lineno - 1
                    unidades.extend(_crear(archivo, "python", "codigo", f"clase {hijo.name}", lineas,
                                           inicio, fin_c, contexto_mod, cabecera=hijo.lineno - 1))
                    cubiertas.update(range(inicio, fin_c + 1))
                cubiertas.update(range(inicio, hijo.lineno))
            elif isinstance(hijo, (ast.If, ast.With, ast.Try)) and nodo is arbol:
                visitar(hijo, contexto_clase)

    visitar(arbol)
    unidades.extend(_bloques_sueltos(archivo, "python", "codigo", lineas, cubiertas, contexto_mod))
    return unidades


def _segmentar_python_indentacion(archivo, lineas):
    unidades, cubiertas = [], set()
    i = 0
    while i < len(lineas):
        m = re.match(r"^(\s*)(async\s+)?def\s+(\w+)", lineas[i])
        if not m:
            i += 1
            continue
        sangria = len(m.group(1))
        inicio = i
        while inicio > 0 and re.match(r"^\s*@", lineas[inicio - 1]):
            inicio -= 1
        fin = i + 1
        while fin < len(lineas) and (not lineas[fin].strip() or len(lineas[fin]) - len(lineas[fin].lstrip()) > sangria):
            fin += 1
        unidades.extend(_crear(archivo, "python", "codigo", m.group(3), lineas, inicio, fin - 1, cabecera=i))
        cubiertas.update(range(inicio, fin))
        i = fin
    unidades.extend(_bloques_sueltos(archivo, "python", "codigo", lineas, cubiertas))
    return unidades


# ---------------------------------------------------------------------------------------------
# Lenguajes con llaves (Java, JavaScript, TypeScript)
# ---------------------------------------------------------------------------------------------
CONTROL = {"if", "for", "while", "switch", "catch", "else", "do", "try", "finally", "synchronized", "return", "with",
           "new", "function", "typeof", "await"}


def _mapa_codigo(texto):
    """Devuelve una copia del texto con cadenas y comentarios reemplazados por espacios
    (misma longitud), para poder emparejar llaves sin confundirse con su contenido."""
    salida = list(texto)
    i, n = 0, len(texto)
    pila_plantilla = []
    while i < n:
        c = texto[i]
        c2 = texto[i:i + 2]
        if c2 == "//":
            j = texto.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                salida[k] = " "
            i = j
        elif c2 == "/*":
            j = texto.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if salida[k] != "\n":
                    salida[k] = " "
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and texto[j] != c and texto[j] != "\n":
                j += 2 if texto[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                salida[k] = " "
            i = j + 1
        elif c == "`":
            j = i + 1
            while j < n and texto[j] != "`":
                if texto[j] == "\\":
                    j += 2
                    continue
                if texto[j:j + 2] == "${":
                    # se conserva la expresión interpolada; se blanquea el texto literal
                    profundidad, k = 1, j + 2
                    while k < n and profundidad:
                        profundidad += texto[k] == "{"
                        profundidad -= texto[k] == "}"
                        k += 1
                    for q in range(j, k):
                        salida[q] = " " if texto[q] in "{}" else salida[q]
                    j = k
                    continue
                if texto[j] != "\n":
                    salida[j] = " "
                j += 1
            i = j + 1
        else:
            i += 1
    return "".join(salida)


_CABECERA_JAVA = re.compile(r"(?:^|[\s;}])(?:(?:public|private|protected|static|final|abstract|synchronized|native|default)\s+)*"
                            r"(?:<[^>]+>\s*)?[\w<>\[\],.?]+(?:\s+[\w<>\[\],.?]+)*\s+(\w+)\s*\([^;{}]*\)\s*(?:throws\s+[\w.,\s]+)?\s*$", re.S)
_CABECERA_CONSTRUCTOR = re.compile(r"(?:^|[\s;}])(?:public|private|protected)\s+(\w+)\s*\([^;{}]*\)\s*(?:throws\s+[\w.,\s]+)?\s*$", re.S)
_CABECERA_JS = [
    re.compile(r"\bfunction\s*\*?\s*(\w*)\s*\([^{}]*\)\s*(?::\s*[^{};]+)?\s*$", re.S),
    re.compile(r"(?:\(([^()]*(?:\([^()]*\)[^()]*)*)\)|(\w+))\s*(?::\s*[\w<>\[\]|, .]+)?\s*=>\s*$", re.S),
    re.compile(r"(?:^|[\s;}])(?:(?:public|private|protected|static|async|readonly|override|get|set)\s+)*\*?\s*(\w+)\s*(?:<[^>]*>)?\s*\([^;{}]*\)\s*(?::\s*[^{};=]+)?\s*$", re.S),
]
_CLASE = re.compile(r"\b(class|interface|enum|record)\s+(\w+)")


def _inicio_sentencia(mapa, pos):
    """Posición donde empieza la sentencia que contiene `pos` (retrocede hasta ; { } de igual nivel)."""
    profundidad = 0
    i = pos - 1
    while i >= 0:
        c = mapa[i]
        if c in ")]":
            profundidad += 1
        elif c in "([":
            if profundidad == 0:
                # estamos dentro de una llamada: router.get('/x', (req,res) => { ... })
                pass
            else:
                profundidad -= 1
        elif c in ";{}" and profundidad == 0:
            return i + 1
        i -= 1
    return 0


def _segmentar_llaves(archivo, texto, lenguaje):
    lineas = texto.splitlines()
    mapa = _mapa_codigo(texto)
    inicio_linea = [0]
    for l in lineas:
        inicio_linea.append(inicio_linea[-1] + len(l) + 1)

    def linea_de(pos):
        lo, hi = 0, len(inicio_linea) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if inicio_linea[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo

    # Emparejar llaves
    pila, pares = [], []
    for i, c in enumerate(mapa):
        if c == "{":
            pila.append(i)
        elif c == "}" and pila:
            pares.append((pila.pop(), i))
    pares.sort()

    funciones, clases = [], []
    for abre, cierra in pares:
        ini = _inicio_sentencia(mapa, abre)
        while ini < abre and mapa[ini].isspace():
            ini += 1
        cab = mapa[ini:abre]
        cab_txt = texto[ini:abre]
        cab_limpia = re.sub(r"@\w+(?:\.\w+)*(?:\((?:[^()]|\([^()]*\))*\))?", " ", cab).strip()
        if _CLASE.search(cab_limpia) and not re.search(r"=>\s*$|\bnew\s", cab_limpia):
            clases.append((abre, cierra, cab_txt.strip()))
            continue
        nombre = None
        if re.search(r"\bnew\s+[\w.<>]+\s*\([^)]*\)\s*$", cab_limpia):
            continue  # clase anónima
        if lenguaje == "java":
            m = _CABECERA_JAVA.search(cab_limpia) or _CABECERA_CONSTRUCTOR.search(cab_limpia)
            if m and m.group(1) not in CONTROL:
                nombre = m.group(1)
        else:
            for k, patron in enumerate(_CABECERA_JS):
                m = patron.search(cab_limpia)
                if m:
                    candidato = next((g for g in m.groups() if g), "") if k != 1 else "handler"
                    if k == 2 and candidato in CONTROL:
                        continue
                    nombre = candidato or "función"
                    break
            if nombre == "handler":
                ruta = re.search(r"\.(get|post|put|patch|delete|all|use)\s*\(\s*['\"`]([^'\"`]*)", cab_txt)
                prop = re.search(r"(\w+)\s*[:=]\s*(?:async\s*)?\(?[^()]*\)?\s*=>\s*$", cab_limpia)
                nombre = f"{ruta.group(1).upper()} {ruta.group(2)}" if ruta else (prop.group(1) if prop else "función flecha")
        if nombre:
            funciones.append((ini, abre, cierra, nombre))

    # Seleccionar funciones: las más externas, salvo que sean muy largas y contengan otras
    # (p. ej. module.exports = function(app) { router.get(...) ... }), en cuyo caso se
    # desciende a sus funciones internas.
    def hijas(padre):
        dentro = [g for g in funciones if g is not padre and (padre is None or (g[1] > padre[1] and g[2] < padre[2]))]
        return [g for g in dentro if not any(h is not g and h[1] < g[1] and h[2] > g[2] for h in dentro)]

    seleccion = []

    def elegir(padre):
        for f in hijas(padre):
            largo = linea_de(f[2]) - linea_de(f[0])
            if largo > MAX_LINEAS and hijas(f):
                elegir(f)
            else:
                seleccion.append(f)

    elegir(None)

    unidades, cubiertas = [], set()
    ctx_archivo = "\n".join(l for l in lineas if re.search(
        r"\b(app|router|server)\.use\s*\(|@UseGuards|@PreAuthorize|@Secured|@RolesAllowed|@EnableWebSecurity|"
        r"SecurityFilterChain|authorizeHttpRequests|authorizeRequests|@CrossOrigin|helmet\(|rateLimit|ThrottlerModule|"
        r"APP_GUARD|csrf\(|cors\(", l))[:1500]
    for ini, abre, cierra, nombre in seleccion:
        li, lf = linea_de(ini), linea_de(cierra)
        # si la sentencia empieza a mitad de línea, incluir la línea completa
        clase = next((c for c in clases if c[0] < abre and c[1] > cierra), None)
        contexto = ((clase[2] + "\n") if clase else "") + ctx_archivo
        unidades.extend(_crear(archivo, lenguaje, "codigo", nombre, lineas, li, lf, contexto.strip(),
                               cabecera=linea_de(abre)))
        cubiertas.update(range(li, lf + 1))
    for abre, cierra, cab in clases:
        cubiertas.update(range(linea_de(abre - len(cab)) if cab else linea_de(abre), linea_de(abre) + 1))
        cubiertas.add(linea_de(cierra))
    # campos/atributos de clase (DTO, entidades) que no pertenecen a métodos: bloque propio por clase
    for abre, cierra, cab in clases:
        miembros = [i for i in range(linea_de(abre) + 1, linea_de(cierra)) if i not in cubiertas and lineas[i].strip()]
        if len(miembros) >= 2:
            nombre_clase = _CLASE.search(cab)
            unidades.extend(_crear(archivo, lenguaje, "codigo", f"clase {nombre_clase.group(2) if nombre_clase else ''}".strip(),
                                   lineas, miembros[0], miembros[-1], cab, meta={"miembros": True}))
            cubiertas.update(miembros)
    unidades.extend(_bloques_sueltos(archivo, lenguaje, "codigo", lineas, cubiertas, ctx_archivo))
    return unidades


# ---------------------------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------------------------
def _segmentar_dockerfile(archivo, texto):
    lineas = texto.splitlines()
    etapas = [i for i, l in enumerate(lineas) if re.match(r"^\s*FROM\s", l, re.I)] or [0]
    etapas.append(len(lineas))
    unidades = []
    for k in range(len(etapas) - 1):
        ini, fin = (0 if k == 0 else etapas[k]), etapas[k + 1] - 1
        unidades.extend(_crear(archivo, "config", "dockerfile", f"etapa {k + 1}", lineas, ini, fin,
                               meta={"archivo_tiene_user": bool(re.search(r"^\s*USER\s+(?!root\b|0\b)", texto, re.M | re.I)),
                                     "ultima_etapa": k == len(etapas) - 2}))
    return unidades


def _bloques_yaml(lineas, nivel_hijos=0):
    """Bloques por clave de un nivel de sangría dado: [(clave, ini, fin)]."""
    bloques = []
    actual = None
    for i, l in enumerate(lineas):
        if not l.strip() or l.lstrip().startswith("#"):
            continue
        sangria = len(l) - len(l.lstrip())
        m = re.match(r"^\s*[\"']?([^\"':#][^:#]*?)[\"']?\s*:(\s|$)", l)
        if sangria == nivel_hijos and m and not l.lstrip().startswith("-"):
            if actual:
                bloques.append(actual)
            actual = [m.group(1).strip(), i, i]
        elif actual and sangria > nivel_hijos:
            actual[2] = i
        elif sangria < nivel_hijos:
            if actual:
                bloques.append(actual)
                actual = None
    if actual:
        bloques.append(actual)
    return [tuple(b) for b in bloques]


def _segmentar_yaml(archivo, texto, subtipo):
    lineas = texto.splitlines()
    unidades = []
    for clave, ini, fin in _bloques_yaml(lineas, 0):
        if subtipo == "compose" and clave in ("services",):
            hijos = _bloques_yaml(lineas[ini + 1:fin + 1], _sangria_hijos(lineas, ini, fin))
            for sub, a, b in hijos:
                unidades.extend(_crear(archivo, "config", subtipo, f"servicio {sub}", lineas, ini + 1 + a, ini + 1 + b,
                                       meta={"servicio_compose": sub}))
            continue
        if subtipo == "openapi" and clave == "paths":
            hijos = _bloques_yaml(lineas[ini + 1:fin + 1], _sangria_hijos(lineas, ini, fin))
            for sub, a, b in hijos:
                unidades.extend(_crear(archivo, "config", subtipo, f"ruta {sub}", lineas, ini + 1 + a, ini + 1 + b))
            continue
        if fin - ini + 1 > MAX_LINEAS and subtipo in ("yaml", "openapi"):
            hijos = _bloques_yaml(lineas[ini + 1:fin + 1], _sangria_hijos(lineas, ini, fin))
            if hijos:
                for sub, a, b in hijos:
                    unidades.extend(_crear(archivo, "config", subtipo, f"{clave}.{sub}", lineas, ini, ini + 1 + b) if a == 0 else
                                    _crear(archivo, "config", subtipo, f"{clave}.{sub}", lineas, ini + 1 + a, ini + 1 + b,
                                           cabecera=ini))
                continue
        unidades.extend(_crear(archivo, "config", subtipo, clave, lineas, ini, fin))
    if not unidades and texto.strip():
        unidades.extend(_crear(archivo, "config", subtipo, Path(archivo).name, lineas, 0, len(lineas) - 1))
    return unidades


def _sangria_hijos(lineas, ini, fin):
    for l in lineas[ini + 1:fin + 1]:
        if l.strip() and not l.lstrip().startswith("#"):
            return len(l) - len(l.lstrip())
    return 2


def _segmentar_properties(archivo, texto, subtipo):
    lineas = texto.splitlines()
    unidades, grupo, prefijo = [], [], None
    for i, l in enumerate(lineas):
        s = l.strip()
        if not s or s.startswith(("#", "!")):
            continue
        clave = re.split(r"[=:\s]", s, maxsplit=1)[0]
        pref = ".".join(clave.split(".")[:2]) if subtipo == "properties" else clave.split("_")[0]
        if prefijo is not None and pref != prefijo and len(grupo) >= 1:
            unidades.extend(_crear(archivo, "config", subtipo, prefijo, lineas, grupo[0], grupo[-1]))
            grupo = []
        prefijo = pref
        grupo.append(i)
    if grupo:
        unidades.extend(_crear(archivo, "config", subtipo, prefijo, lineas, grupo[0], grupo[-1]))
    # unir grupos de una sola línea consecutivos para dar contexto
    fusion = []
    for u in unidades:
        if fusion and len(fusion[-1].lineas) < 4 and len(u.lineas) < 4 and u.linea_inicio - fusion[-1].linea_fin <= 3:
            prev = fusion[-1]
            prev.lineas += u.lineas
            prev.texto += "\n" + u.texto
            prev.nombre = f"{prev.nombre}, {u.nombre}"
        else:
            fusion.append(u)
    return fusion


def _segmentar_manifiesto(archivo, texto):
    lineas = texto.splitlines()
    nombre = Path(archivo).name.lower()
    if nombre == "package.json":
        unidades = []
        for clave in ("dependencies", "devDependencies", "scripts", "engines"):
            m = re.search(r"^\s*\"" + clave + r"\"\s*:\s*\{", texto, re.M)
            if not m:
                continue
            ini = texto[:m.start()].count("\n") + (1 if texto[m.start()] == "\n" else 0)
            fin = ini
            while fin < len(lineas) and not re.match(r"^\s*\}", lineas[fin]):
                fin += 1
            unidades.extend(_crear(archivo, "config", "manifiesto", clave, lineas, ini, fin))
        return unidades
    if nombre == "pom.xml":
        unidades = []
        for m in re.finditer(r"<(dependency|plugin|parent)>.*?</\1>", texto, re.S):
            ini = texto[:m.start()].count("\n")
            fin = texto[:m.end()].count("\n")
            unidades.extend(_crear(archivo, "config", "manifiesto", m.group(1), lineas, ini, fin))
        # agrupar dependencias de a 6 para que cada unidad tenga contexto suficiente
        agrupadas = []
        for k in range(0, len(unidades), 6):
            grupo = unidades[k:k + 6]
            u = grupo[0]
            for g in grupo[1:]:
                u.lineas += g.lineas
                u.texto += "\n" + g.texto
            u.nombre = "dependencias"
            agrupadas.append(u)
        return agrupadas
    return _crear(archivo, "config", "manifiesto", Path(archivo).name, lineas, 0, len(lineas) - 1)


def _openapi_json_a_yaml(texto):
    import yaml
    try:
        return yaml.safe_dump(json.loads(texto), sort_keys=False, allow_unicode=True)
    except (ValueError, yaml.YAMLError):
        return None


# ---------------------------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------------------------
def segmentar(archivo, texto, lenguaje=None, subtipo=None):
    """Divide el contenido de un archivo en unidades de análisis."""
    if lenguaje is None or subtipo is None:
        t = tipo_archivo(archivo, texto)
        if t is None:
            return []
        lenguaje, subtipo = t
    texto = texto.replace("\r\n", "\n").replace("\t", "    ")
    if subtipo == "codigo":
        if lenguaje == "python":
            return _segmentar_python(archivo, texto)
        if lenguaje in ("java", "javascript", "typescript", "kotlin"):
            return _segmentar_llaves(archivo, texto, lenguaje)
        return []
    if subtipo == "dockerfile":
        return _segmentar_dockerfile(archivo, texto)
    if subtipo in ("compose", "yaml"):
        return _segmentar_yaml(archivo, texto, subtipo)
    if subtipo == "openapi":
        if texto.lstrip().startswith("{"):
            convertido = _openapi_json_a_yaml(texto)
            if convertido is None:
                return []
            unidades = _segmentar_yaml(archivo, convertido, "openapi")
            for u in unidades:
                u.meta["lineas_aproximadas"] = True
                primera = u.texto.strip().splitlines()[0].split(":")[0].strip().strip("'\"")
                pos = texto.find(f'"{primera}"')
                if pos >= 0:
                    base = texto[:pos].count("\n") + 1
                    u.lineas = [base + k for k in range(len(u.lineas))]
            return unidades
        return _segmentar_yaml(archivo, texto, "openapi")
    if subtipo in ("properties", "env"):
        return _segmentar_properties(archivo, texto, subtipo)
    if subtipo == "manifiesto":
        return _segmentar_manifiesto(archivo, texto)
    return []

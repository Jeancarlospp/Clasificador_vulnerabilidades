"""Preprocesamiento léxico del código: limpieza, normalización y tokenización.

Se aplica exactamente igual en entrenamiento y en el análisis de proyectos.

1. ``limpiar_codigo``: elimina comentarios que "delatan" la etiqueta en los conjuntos de prueba
   de reglas (``// ruleid``, ``# ok``, ``BAD``, ``vulnerable``...). Sin este paso el modelo
   aprendería los comentarios en lugar del código.
2. ``neutralizar_identificadores``: reemplaza nombres que revelan la etiqueta (``bad1``,
   ``goodG2B``, ``BenchmarkTest00042``, ``unsafe_query``) por un identificador neutro.
3. ``tokenizar``: tokens propios de código (identificadores, operadores y marcadores de
   interpolación) con sub-tokens camelCase / snake_case.
"""

import re
import textwrap

MARCAS = re.compile(
    r"ruleid|todoruleid|todook|deepok|deepruleid|\bok\s*:|\$\s*(Alert|Source|Sink|MISSING|SPURIOUS)|"
    r"\bBAD\b|\bGOOD\b|NOT\s+OK|\bOK\b|vulnerab|insecure|\bunsafe\b|\bsafe\b|\bsecure\b|"
    r"noncompliant|compliant|sanitiz|true\s+positive|false\s+positive|\bFP\b|\bTP\b|\bFN\b|"
    r"should\s+(not\s+)?(be\s+)?(flag|alert|report|detect|match)|taint|\bsink\b|\bsource\b|"
    r"inject|xss|cwe|ssrf|traversal|\bnosec\b|nosemgrep|codeql|semgrep|dangerous|never\s+do|"
    r"intentional|attack|exploit|evil|malicious|benchmark|kics|\bfix\b|\bfixed\b|bypass|hack",
    re.IGNORECASE,
)
COMENTARIO_LINEA = re.compile(r"^\s*(#(?!!)|//|/\*|\*(?!\*)|<!--|--(?!-))")
COMENTARIO_FINAL = re.compile(r"(\s+(#|//)\s*.*$|/\*.*?\*/\s*$)")


def limpiar_linea(linea):
    """Devuelve la línea sin comentarios que delatan la etiqueta, o None si debe eliminarse."""
    if COMENTARIO_LINEA.match(linea):
        return None if MARCAS.search(linea) else linea
    m = COMENTARIO_FINAL.search(linea)
    if m and MARCAS.search(m.group(0)):
        return linea[: m.start()].rstrip()
    return linea


def limpiar_codigo(codigo):
    lineas = (limpiar_linea(l) for l in str(codigo).replace("\r\n", "\n").splitlines())
    return textwrap.dedent("\n".join(l for l in lineas if l is not None)).strip("\n")


# ---------------------------------------------------------------------------------------------
# Neutralización de identificadores que delatan la etiqueta
# ---------------------------------------------------------------------------------------------
APIS_PERMITIDAS = {
    "safe_load", "safeload", "safeloader", "csafeloader", "safe_join", "safe_dump", "secure_filename", "is_safe_url",
    "mark_safe", "html_safe", "safe_str_cmp", "securerandom", "secure", "httponly", "ssl_verify", "safestring",
    "safe_substitute", "safejson", "url_has_allowed_host_and_scheme", "set_secure", "setsecure", "secure_cookie",
    "session_cookie_secure", "csrf_cookie_secure", "secure_proxy_ssl_header", "issecure", "is_secure",
    "secure_compare", "status_ok", "http_ok", "ok", "okhttp", "okhttpclient", "isok", "is_ok", "res_ok",
}
PARTES_MARCA = {"bad", "good", "safe", "unsafe", "insecure", "secure", "vuln", "vulnerable", "vulnerability", "vulnerabilities", "noncompliant",
                "compliant", "positive", "negative", "benign", "malicious", "evil", "tainted", "untainted",
                "sanitized", "benchmark", "exploit", "attack", "attacker", "hacker", "pwn", "pwned"}
_IDENT = re.compile(r"(?<![\w$])(\$?)([A-Za-z_][A-Za-z0-9_]*)")
_PARTES = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+|_+")
_BENCHMARK = re.compile(r"BenchmarkTest\d+|benchmarktest\d+")


def neutralizar_identificadores(codigo):
    """Reemplaza por ``ident`` los identificadores cuyas partes revelan la etiqueta."""
    codigo = _BENCHMARK.sub("Handler", codigo)

    def repl(m):
        signo, nombre = m.group(1), m.group(2)
        if nombre.lower() in APIS_PERMITIDAS:
            return m.group(0)
        partes = _PARTES.findall(nombre)
        if "".join(partes) != nombre or not any(p.lower() in PARTES_MARCA for p in partes):
            return m.group(0)
        return signo + "ident"

    return _IDENT.sub(repl, codigo)


def preparar(codigo):
    """Entrada textual del modelo: código limpio y con identificadores neutralizados."""
    return neutralizar_identificadores(limpiar_codigo(codigo))


# ---------------------------------------------------------------------------------------------
# Tokenización
# ---------------------------------------------------------------------------------------------
PATRON_TOKENS = re.compile(
    r"\$\{|#\{|[A-Za-z_$@][\w$]*|\d+|==+|!=+|<=|>=|&&|\|\||\+=|->|=>|::|<<|>>|\*\*|<%|%>|<\?|"
    r"[{}()\[\];=+\-*/<>.,'\"`%$#!&|:?\\]"
)
_SUBTOKENS = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")


def tokenizar(texto):
    """Tokens de código en minúsculas + sub-tokens de identificadores compuestos."""
    tokens = []
    for t in PATRON_TOKENS.findall(texto):
        tl = t.lower()
        if tl.isdigit() and len(tl) > 2:
            tl = "<num>"
        tokens.append(tl)
        if len(t) > 3 and (re.search(r"[a-z][A-Z]", t) or "_" in t.strip("_")):
            partes = [p.lower() for p in _SUBTOKENS.findall(t) if len(p) > 1]
            if len(partes) > 1:
                tokens.extend(partes)
    return tokens


def tokenizar_preparado(texto):
    """Tokenizador usado por el vectorizador TF-IDF (el texto ya viene preparado)."""
    return tokenizar(texto)

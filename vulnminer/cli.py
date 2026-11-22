"""Interfaz de línea de comandos de vulnminer (RF07).

    vulnminer scan . --standards owasp2025,api2023 --format json,html --output ./reportes
    vulnminer fragmento archivo.py            (analiza un fragmento suelto)
    vulnminer fragmento --codigo "os.system('ping ' + host)" --lenguaje python
    vulnminer info                            (modelo, métricas y categorías evaluadas)
"""

import argparse
import sys
from pathlib import Path

from . import __version__


def _lista(valor, validos, nombre):
    elementos = [v.strip().lower() for v in valor.split(",") if v.strip()]
    malos = [v for v in elementos if v not in validos]
    if malos:
        raise argparse.ArgumentTypeError(f"{nombre} no válido(s): {', '.join(malos)}. Opciones: {', '.join(validos)}")
    return elementos


def comando_scan(args):
    from .analizador import analizar_proyecto, cargar_modelo
    from .reportes import consola, escribir_html, escribir_json

    raiz = Path(args.ruta).resolve()
    if not raiz.is_dir():
        print(f"error: {raiz} no es un directorio", file=sys.stderr)
        return 2
    try:
        estandares = _lista(args.standards, ["owasp2025", "api2023"], "estándar")
        formatos = _lista(args.format, ["json", "html"], "formato")
    except argparse.ArgumentTypeError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if not estandares or not formatos:
        print("error: indique al menos un estándar y un formato", file=sys.stderr)
        return 2
    if not args.quiet:
        print(f"Analizando {raiz} ...", file=sys.stderr)
    modelo = cargar_modelo(args.modelo)
    progreso = None if args.quiet else (lambda m: print("  " + m, file=sys.stderr))
    resultado = analizar_proyecto(raiz, modelo, estandares, args.threshold, args.include_tests, progreso)
    salida = Path(args.output)
    if not salida.is_absolute():
        salida = Path.cwd() / salida
    salida.mkdir(parents=True, exist_ok=True)
    rutas = []
    if "json" in formatos:
        rutas.append(escribir_json(resultado, salida / "analisis.json"))
    if "html" in formatos:
        rutas.append(escribir_html(resultado, salida / "analisis.html"))
    rel = [p.relative_to(Path.cwd()) if p.is_relative_to(Path.cwd()) else p for p in rutas]
    print(consola(resultado, rel, max_hallazgos=args.max_console, detalle=not args.summary))
    return 0


def comando_fragmento(args):
    from . import caracteristicas as C
    from .analizador import analizar_unidades, cargar_modelo
    from .catalogo import nombre_categoria
    from .segmentacion import EXT_LENGUAJE, Unidad, segmentar

    if args.codigo:
        codigo = args.codigo
    elif args.archivo and args.archivo != "-":
        codigo = Path(args.archivo).read_text(encoding="utf-8", errors="ignore")
    else:
        codigo = sys.stdin.read()
    lenguaje = args.lenguaje
    if not lenguaje and args.archivo and args.archivo != "-":
        lenguaje = EXT_LENGUAJE.get(Path(args.archivo).suffix.lower())
    lenguaje = lenguaje or _adivinar_lenguaje(codigo)
    nombre = args.archivo if args.archivo and args.archivo != "-" else f"fragmento.{ {'python': 'py', 'java': 'java', 'javascript': 'js', 'typescript': 'ts'}.get(lenguaje, 'txt') }"
    unidades = segmentar(nombre, codigo) if args.archivo and args.archivo != "-" else []
    if not unidades:
        lineas = codigo.splitlines()
        unidades = [Unidad(nombre, lenguaje, "codigo", "fragmento", list(range(1, len(lineas) + 1)), codigo)]
    modelo = cargar_modelo(args.modelo)
    detectados = {id(d["unidad"]): d for d in analizar_unidades(modelo, unidades, umbral=args.threshold)}
    probas = modelo.predecir(unidades, args.threshold)
    print(f"Lenguaje: {lenguaje} | unidades analizadas: {len(unidades)} | umbral: {args.threshold or modelo.umbral}")
    for u, p in zip(unidades, probas):
        d = detectados.get(id(u))
        print("\n" + "-" * 60)
        print(f"{u.nombre} (líneas {u.linea_inicio}-{u.linea_fin})")
        print(f"Predicción: {'VULNERABLE' if p['vulnerable'] else 'no vulnerable'}  P(vulnerable)={p['probabilidad']:.3f}")
        if d:
            cats = [f"{c} ({q:.2f}) {nombre_categoria(c)}" for c, q in d["t10"] + d["api"]]
            print("Categorías: " + ("; ".join(cats) if cats else
                                    f"pendiente de revisión (sugerida {p['categoria_sugerida'][0]} {p['categoria_sugerida'][1]:.2f})"))
            if d["cwe"]:
                print(f"CWE: {d['cwe']}")
            print(f"Línea más relevante: {d['linea']}")
        activos = [n for n, v in zip(C.nombres_caracteristicas(), C.vector(u)) if v > 0 and n.startswith("x_")]
        ev = C.evidencias(u)
        if ev:
            print("Indicadores:")
            for n, l, t in ev[:8]:
                print(f"  línea {l}: {C.DESCRIPCION[n]} -> {t[:90]}")
        if activos:
            print("Patrones combinados: " + ", ".join(activos))
    return 0


def _adivinar_lenguaje(codigo):
    import re

    puntos = {"python": len(re.findall(r"^\s*(def |import |from \w+ import|@\w+)|:\s*$|\bself\b|\bNone\b", codigo, re.M)),
              "java": len(re.findall(r"\b(public|private|protected|void|String|new \w+\(|@\w+Mapping|throws)\b", codigo)),
              "typescript": len(re.findall(r":\s*(string|number|boolean|any|Promise<)|@(Controller|Injectable|Get|Post)\(|\binterface\b", codigo)),
              "javascript": len(re.findall(r"\b(const|let|var|function|require\(|=>|module\.exports|req\.|res\.)", codigo))}
    return max(puntos, key=puntos.get)


def comando_info(args):
    from .analizador import cargar_modelo
    from .catalogo import CATEGORIAS, nombre_categoria

    m = cargar_modelo(args.modelo)
    md = m.metadatos
    print(f"vulnminer {__version__}")
    print(f"Detector: {m.algoritmo_detector} (umbral {m.umbral}) | Categorías: {m.algoritmo_categorias}")
    print(f"Entrenado: {md.get('fecha')} | particiones: {md.get('particiones')}")
    d = md.get("detector_prueba", {})
    if d:
        print(f"Prueba (detector): precision={d['precision']:.3f} recall={d['recall']:.3f} f1={d['f1']:.3f} auc={d['roc_auc']:.3f}")
    print("\nCategorías:")
    for c in CATEGORIAS:
        if c in m.categorias:
            x = md.get("por_categoria", {}).get(c, {})
            print(f"  {c:11s} evaluada     F1 prueba={x.get('f1', float('nan')):.2f}  {nombre_categoria(c)}")
        else:
            print(f"  {c:11s} NO evaluada  {m.no_evaluadas.get(c, 'sin clasificador')}  {nombre_categoria(c)}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="vulnminer", description="Clasificador de posibles vulnerabilidades en microservicios "
                                 "(OWASP Top 10:2025 y OWASP API Security Top 10:2023) basado en minería de datos.")
    ap.add_argument("--version", action="version", version=f"vulnminer {__version__}")
    sub = ap.add_subparsers(dest="comando", required=True)

    s = sub.add_parser("scan", help="analiza un proyecto de microservicios desde su directorio raíz")
    s.add_argument("ruta", nargs="?", default=".", help="directorio raíz del proyecto (por defecto: el actual)")
    s.add_argument("--standards", "--estandares", default="owasp2025,api2023", help="owasp2025,api2023")
    s.add_argument("--format", "--formato", default="json,html", help="json,html")
    s.add_argument("--output", "--salida", default="./reportes", help="carpeta de los reportes")
    s.add_argument("--threshold", "--umbral", type=float, default=None, help="umbral de decisión (por defecto, el calibrado)")
    s.add_argument("--include-tests", action="store_true", help="incluye carpetas y archivos de pruebas")
    s.add_argument("--max-console", type=int, default=None, help="máximo de hallazgos detallados en consola")
    s.add_argument("--summary", action="store_true", help="solo el resumen en consola")
    s.add_argument("--modelo", default=None, help=argparse.SUPPRESS)
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=comando_scan)

    f = sub.add_parser("fragmento", help="analiza un fragmento de código suelto")
    f.add_argument("archivo", nargs="?", help="archivo con el fragmento ('-' = entrada estándar)")
    f.add_argument("--codigo", help="fragmento como texto")
    f.add_argument("--lenguaje", choices=["python", "java", "javascript", "typescript"])
    f.add_argument("--threshold", "--umbral", type=float, default=None)
    f.add_argument("--modelo", default=None, help=argparse.SUPPRESS)
    f.set_defaults(func=comando_fragmento)

    i = sub.add_parser("info", help="muestra el modelo, sus métricas y las categorías evaluadas")
    i.add_argument("--modelo", default=None, help=argparse.SUPPRESS)
    i.set_defaults(func=comando_info)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

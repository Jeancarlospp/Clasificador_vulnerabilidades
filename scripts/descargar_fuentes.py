"""Descarga las fuentes públicas usadas para construir el dataset y para la evaluación.

- ``fuentes/``                : repositorios con ejemplos etiquetados (entrenamiento).
- ``evaluacion/proyectos/``   : proyectos de microservicios que NO participan en el
                                entrenamiento (prueba funcional de la herramienta).

Solo se descargan las carpetas necesarias (clonado superficial y disperso).
La versión exacta (commit) de cada repositorio queda registrada en
``datos/versiones_fuentes.json`` para garantizar la trazabilidad.

Uso:
    python scripts/descargar_fuentes.py            # todo
    python scripts/descargar_fuentes.py --solo entrenamiento
    python scripts/descargar_fuentes.py --solo evaluacion
"""

import argparse
import json
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
FUENTES = BASE / "fuentes"
PROYECTOS = BASE / "evaluacion" / "proyectos"

# nombre -> (repositorio, carpetas a descargar o None para todo el repositorio)
ENTRENAMIENTO = {
    # Ejemplos etiquetados (vulnerable / seguro)
    "semgrep-rules": ("semgrep/semgrep-rules", ["java", "python", "javascript", "typescript", "dockerfile", "yaml", "generic", "json"]),
    "codeql": ("github/codeql", ["java/ql/test/query-tests/security", "java/ql/test/experimental/query-tests/security",
                                 "javascript/ql/test/query-tests/Security", "javascript/ql/test/experimental/Security",
                                 "python/ql/test/query-tests/Security", "python/ql/test/experimental/query-tests/Security"]),
    "benchmark-java": ("OWASP-Benchmark/BenchmarkJava", ["src/main/java/org/owasp/benchmark/testcode", "expectedresults-1.2.csv"]),
    "benchmark-python": ("OWASP-Benchmark/BenchmarkPython", None),
    "kics": ("Checkmarx/kics", ["assets/queries/dockerfile", "assets/queries/dockerCompose", "assets/queries/openAPI"]),
    "securityeval": ("s2e-lab/SecurityEval", ["Testcases_Insecure_Code", "dataset.jsonl"]),
    # Código de aplicaciones reales (clase no vulnerable)
    "benigno/full-stack-fastapi-template": ("tiangolo/full-stack-fastapi-template", ["backend"]),
    "benigno/fastapi-realworld": ("nsidnev/fastapi-realworld-example-app", ["app"]),
    "benigno/nestjs-realworld": ("lujakob/nestjs-realworld-example-app", ["src"]),
    "benigno/nest-samples": ("nestjs/nest", ["sample"]),
    "benigno/express-realworld": ("gothinkster/node-express-realworld-example-app", ["src"]),
    "benigno/spring-boot-realworld": ("gothinkster/spring-boot-realworld-example-app", ["src"]),
    "benigno/flask": ("pallets/flask", ["src"]),
    "benigno/express": ("expressjs/express", ["lib", "examples"]),
    "benigno/node-express-boilerplate": ("hagopj13/node-express-boilerplate", ["src"]),
    "benigno/express-rest-boilerplate": ("danielfsousa/express-rest-boilerplate", ["src"]),
    "benigno/express-typescript-boilerplate": ("w3tecch/express-typescript-boilerplate", ["src"]),
    "benigno/nestjs-boilerplate": ("brocoders/nestjs-boilerplate", ["src"]),
    "benigno/awesome-nest-boilerplate": ("NarHakobyan/awesome-nest-boilerplate", ["src"]),
    "benigno/nest-cli": ("nestjs/nest-cli", ["lib", "actions", "commands"]),
    "benigno/jhipster-sample-app": ("jhipster/jhipster-sample-app", ["src/main/java", "src/main/webapp/app"]),
    "benigno/piggymetrics": ("sqshq/piggymetrics", None),
    "benigno/polls-app": ("callicoder/spring-security-react-ant-design-polls-app", ["polling-app-server/src/main"]),
    "benigno/mall-swarm": ("macrozheng/mall-swarm", None),
    "benigno/shiro": ("apache/shiro", ["core/src/main", "web/src/main"]),
    "benigno/keycloak-quickstarts": ("keycloak/keycloak-quickstarts", None),
    "benigno/microblog": ("miguelgrinberg/microblog", ["app"]),
    "benigno/dispatch": ("Netflix/dispatch", ["src/dispatch"]),
    "benigno/django-realworld": ("gothinkster/django-realworld-example-app", ["conduit"]),
    "benigno/fastapi-tdd-docker": ("testdrivenio/fastapi-tdd-docker", ["project/app"]),
    "benigno/netbox": ("netbox-community/netbox", ["netbox"]),
    "benigno/starlette": ("encode/starlette", ["starlette"]),
    # Documentos oficiales de los estándares (correspondencias CWE)
    "owasp-top10": ("OWASP/Top10", ["2025/docs/en"]),
    "owasp-api": ("OWASP/API-Security", ["editions/2023/en"]),
}

EVALUACION = {
    # Proyectos vulnerables con vulnerabilidades documentadas
    "crAPI": ("OWASP/crAPI", ["services", "deploy/docker"]),
    "VAmPI": ("erev0s/VAmPI", None),
    "dvws-node": ("snoopysecurity/dvws-node", None),
    "restaurant-api": ("theowni/Damn-Vulnerable-RESTaurant-API-Game", None),
    # Proyectos de microservicios de referencia (sin vulnerabilidades intencionales)
    "petclinic-microservices": ("spring-petclinic/spring-petclinic-microservices", None),
    "microservices-demo": ("GoogleCloudPlatform/microservices-demo", ["src", "docker-compose.yml"]),
    # Conjuntos de fragmentos para evaluación a nivel de código
    "juice-shop": ("juice-shop/juice-shop", ["data/static/codefixes"]),
    "cheatsheets": ("OWASP/CheatSheetSeries", ["cheatsheets"]),
}


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def descargar(destino: Path, repo: str, rutas):
    url = f"https://github.com/{repo}.git"
    if (destino / ".git").exists():
        print(f"  ya existe: {destino.relative_to(BASE)}")
    else:
        destino.parent.mkdir(parents=True, exist_ok=True)
        print(f"  descargando {repo} ...")
        if rutas:
            git("clone", "--depth", "1", "--filter=blob:none", "--sparse", url, str(destino))
            git("sparse-checkout", "set", "--no-cone", *rutas, cwd=destino)
        else:
            git("clone", "--depth", "1", url, str(destino))
    return git("rev-parse", "HEAD", cwd=destino)


def descargar_cwe():
    """Catálogo oficial de debilidades de MITRE (nombres de los CWE)."""
    import urllib.request
    destino = FUENTES / "cwe" / "cwec_latest.xml.zip"
    if not destino.exists():
        destino.parent.mkdir(parents=True, exist_ok=True)
        print("  descargando catálogo CWE de MITRE ...")
        urllib.request.urlretrieve("https://cwe.mitre.org/data/xml/cwec_latest.xml.zip", destino)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--solo", choices=["entrenamiento", "evaluacion"])
    args = ap.parse_args()
    archivo_versiones = BASE / "datos" / "versiones_fuentes.json"
    versiones = json.loads(archivo_versiones.read_text()) if archivo_versiones.exists() else {}
    grupos = []
    if args.solo != "evaluacion":
        grupos.append(("entrenamiento", FUENTES, ENTRENAMIENTO))
    if args.solo != "entrenamiento":
        grupos.append(("evaluacion", PROYECTOS, EVALUACION))
    if args.solo != "evaluacion":
        descargar_cwe()
    for nombre_grupo, raiz, repos in grupos:
        print(f"[{nombre_grupo}]")
        for nombre, (repo, rutas) in repos.items():
            commit = descargar(raiz / nombre, repo, rutas)
            versiones[nombre] = {"repositorio": f"https://github.com/{repo}", "commit": commit,
                                 "uso": nombre_grupo, "carpetas": rutas or ["(todo)"]}
    archivo_versiones.parent.mkdir(exist_ok=True)
    archivo_versiones.write_text(json.dumps(versiones, indent=2, ensure_ascii=False))
    print(f"Versiones registradas en {archivo_versiones.relative_to(BASE)}")


if __name__ == "__main__":
    main()

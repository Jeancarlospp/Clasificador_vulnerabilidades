# vulnminer — Clasificador de vulnerabilidades en microservicios

Herramienta de línea de comandos que analiza un proyecto de microservicios desde su directorio raíz y
reporta posibles vulnerabilidades clasificadas según **OWASP Top 10:2025** y **OWASP API Security Top
10:2023**. El componente central es un **modelo de minería de datos** entrenado y evaluado con la
metodología **SEMMA** (Sample, Explore, Modify, Model, Assess). No usa LLM ni depende de herramientas de
análisis estático externas.

Laboratorio 1 · Desarrollo de Software Seguro · Universidad de las Fuerzas Armadas ESPE.

```
cd proyecto-microservicios
vulnminer scan . --standards owasp2025,api2023 --format json,html --output ./reportes
```

## Instalación

Requisitos: Python 3.10 o superior (probado con 3.12) y `git`.

```bash
git clone https://github.com/Jeancarlospp/Clasificador_vulnerabilidades.git
cd Clasificador_vulnerabilidades
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt      # dependencias de la herramienta, notebooks y pruebas
pip install -e .                     # instala el comando `vulnminer`
```

El modelo entrenado (`vulnminer/modelos/vulnminer.joblib`) viene incluido: la herramienta **no necesita
volver a entrenar** para analizar un proyecto.

## Uso

### Analizar un proyecto de microservicios

```bash
cd ruta/al/proyecto
vulnminer scan . --standards owasp2025,api2023 --format json,html --output ./reportes
```

| Opción | Descripción | Por defecto |
|---|---|---|
| `ruta` | Directorio raíz del proyecto | `.` |
| `--standards` | `owasp2025`, `api2023` o ambos | ambos |
| `--format` | `json`, `html` o ambos | ambos |
| `--output` | Carpeta de los reportes | `./reportes` |
| `--threshold` | Umbral de decisión del modelo (0–1) | calibrado en validación |
| `--include-tests` | Analiza también carpetas y archivos de pruebas | no |
| `--summary` | Muestra solo el resumen en consola | no |
| `--max-console N` | Máximo de hallazgos detallados en consola | todos |

La herramienta:

1. Descubre los microservicios (manifiestos `package.json`, `pom.xml`, `build.gradle`, `requirements.txt`,
   `pyproject.toml`, `Dockerfile` y servicios de `docker-compose`) y sus tecnologías (NestJS, Express,
   Spring Boot, FastAPI, Flask, Django...).
2. Analiza código **Java, Python, JavaScript y TypeScript** y archivos de configuración: `application.yml`,
   `application.properties`, `.env`, `Dockerfile`, `docker-compose.yml`, especificaciones OpenAPI/Swagger y
   manifiestos de dependencias.
3. Divide cada archivo en unidades (funciones, *handlers*, bloques de configuración), aplica el pipeline y el
   modelo entrenado, y asigna las categorías OWASP con una probabilidad.
4. Genera `reportes/analisis.json` y `reportes/analisis.html` y un resumen en consola.

Cada hallazgo incluye: identificador, microservicio, archivo, línea, descripción, evidencia técnica
(fragmento, líneas que más influyen en la predicción e indicadores de análisis estático), categoría OWASP
Top 10:2025, categoría API Security Top 10:2023, CWE, confianza del modelo, severidad estimada con su
justificación, recomendación y estado de verificación. Si el modelo no tiene evidencia suficiente para
asignar una categoría, el hallazgo queda como **pendiente de revisión**.

### Otros comandos

```bash
vulnminer fragmento archivo.py                                   # analiza un fragmento suelto
vulnminer fragmento --codigo "os.system('ping ' + host)" --lenguaje python
vulnminer info                                                   # modelo, métricas y categorías evaluadas
```

## Estructura del repositorio

| Ruta | Contenido |
|---|---|
| `vulnminer/` | Paquete de la herramienta: segmentación, características, modelo, análisis, severidad, reportes y CLI |
| `vulnminer/modelos/vulnminer.joblib` | Modelo entrenado con su pipeline de preprocesamiento |
| `vulnminer/datos/mapeo_cwe.json` | Correspondencias CWE → OWASP (oficiales y extendidas) |
| `datos/dataset.csv` | Dataset etiquetado (unidades de código y configuración) |
| `datos/diccionario_datos.csv` | Diccionario de datos |
| `datos/correspondencias_cwe_owasp.csv` | Tabla de correspondencias CWE–OWASP |
| `datos/versiones_fuentes.json` | Repositorios y commits de las fuentes de datos |
| `notebooks/01_sample.ipynb` … `05_assess.ipynb` | Las cinco fases de SEMMA, ejecutadas |
| `scripts/` | Descarga de fuentes, construcción del dataset, entrenamiento y evaluación |
| `resultados/` | Comparación de algoritmos, métricas de prueba y evaluación externa |
| `evaluacion/verdad_terreno.json` | Vulnerabilidades documentadas de los proyectos de evaluación |
| `informe/` | Informe técnico (LaTeX y PDF) |
| `tests/` | Pruebas automáticas (`pytest`) |

## Reproducir el proceso completo

```bash
python scripts/descargar_fuentes.py          # repositorios públicos (fuentes/ y evaluacion/proyectos/)
python scripts/construir_mapeo_cwe.py        # correspondencias CWE–OWASP desde los documentos oficiales
python scripts/generar_casos_controlados.py  # casos controlados de API (semilla fija)
python scripts/construir_dataset.py          # SAMPLE: dataset etiquetado y partición 70/15/15
python scripts/entrenar.py                   # MODIFY + MODEL: comparación de algoritmos y modelo final
python scripts/evaluar.py                    # ASSESS: proyectos de microservicios y fragmentos externos
python scripts/generar_notebooks.py          # ejecuta los notebooks SEMMA
pytest                                       # pruebas automáticas
```

## Resultados

Los resultados detallados están en `resultados/` y en los notebooks `04_model` y `05_assess`.

<!-- RESULTADOS -->

## Limitaciones

- El análisis es **estático y por unidad**: los hallazgos son *potenciales* y deben verificarse. Las fallas
  de autorización (API1, API5), de lógica de negocio y de monitoreo pueden requerir validación dinámica o
  revisión manual.
- **API6:2023** (flujos de negocio sensibles) se declara *no evaluada*: depende de la lógica de cada negocio
  y no hay datos etiquetados suficientes. Las categorías con pocos ejemplos se informan con su soporte.
- Go, C#, PHP y otros lenguajes se detectan pero no se analizan; se listan como no soportados en el reporte.

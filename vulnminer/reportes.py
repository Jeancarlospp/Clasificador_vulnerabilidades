"""Reportes de resultados: consola, JSON y HTML (RF09)."""

import html
import json
from collections import Counter, defaultdict
from pathlib import Path

from .catalogo import API2023, OWASP2025, nombre_categoria
from .severidad import NIVELES

LINEA = "=" * 40
GUION = "-" * 40


# ---------------------------------------------------------------------------------------------
# Consola
# ---------------------------------------------------------------------------------------------
def consola(resultado, rutas=(), max_hallazgos=None, detalle=True):
    r = resultado["resumen"]
    out = [LINEA, "VULNMINER - SECURITY SCAN", LINEA, "",
           f"Proyecto: {resultado['proyecto']}", "",
           f"Microservicios identificados: {r['microservicios']}",
           f"Archivos analizados: {r['archivos_analizados']}",
           f"Unidades analizadas: {r['unidades_analizadas']}",
           f"Hallazgos potenciales: {r['hallazgos']}", ""]
    if r.get("archivos_omitidos"):
        out.insert(-2, "Archivos omitidos: " + ", ".join(f"{v} ({k})" for k, v in r["archivos_omitidos"].items()))
    if r.get("archivos_no_soportados"):
        out.insert(-2, "Lenguajes no soportados (no analizados): " +
                   ", ".join(f"{k} {v} archivo(s)" for k, v in r["archivos_no_soportados"].items()))
    if not r["archivos_analizados"]:
        out += ["AVISO: no se encontraron archivos soportados (Python, Java, JavaScript/TypeScript, Dockerfile,",
                "docker-compose, YAML, properties, .env o manifiestos de dependencias). Revise la ruta indicada.", ""]
    sev = Counter(h["severidad"] for h in resultado["hallazgos"])
    if resultado["hallazgos"]:
        out.append("Por severidad: " + ", ".join(f"{n} {sev.get(n, 0)}" for n in reversed(NIVELES)))
        por_servicio = Counter(h["microservicio"] for h in resultado["hallazgos"])
        out.append("Por microservicio: " + ", ".join(f"{k} {v}" for k, v in por_servicio.most_common()))
        out.append("")
    hallazgos = resultado["hallazgos"] if max_hallazgos is None else resultado["hallazgos"][:max_hallazgos]
    if detalle:
        for h in hallazgos:
            t10 = ", ".join(c["codigo"] for c in h["owasp_top10"]) or "-"
            api = ", ".join(c["codigo"] for c in h["owasp_api"]) or "-"
            out += [GUION, f"HALLAZGO {h['id'].split('-')[-1]}", GUION, "",
                    f"Servicio: {h['microservicio']}", f"Archivo: {h['archivo']}", f"Linea: {h['linea']}", "",
                    f"OWASP Top 10: {t10}", f"OWASP API: {api}"]
            if h["cwe"]:
                out.append(f"CWE: {h['cwe']['id']} {h['cwe']['nombre']}")
            out += ["", "Problema potencial:", h["descripcion"], "",
                    f"Confianza del modelo: {h['confianza']:.2f}", f"Severidad estimada: {h['severidad']}",
                    f"Estado: {h['estado']}", ""]
        if max_hallazgos is not None and len(resultado["hallazgos"]) > max_hallazgos:
            out.append(f"... {len(resultado['hallazgos']) - max_hallazgos} hallazgos más en los reportes.")
            out.append("")
    no_eval = [c for c, d in resultado["categorias"].items() if d["estado"] == "no evaluada"]
    if no_eval:
        out += [f"Categorías no evaluadas: {', '.join(no_eval)}", ""]
    if rutas:
        out += [GUION, "REPORTES GENERADOS", GUION, ""] + [str(p) for p in rutas] + [""]
    out.append(LINEA)
    return "\n".join(out)


# ---------------------------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------------------------
def escribir_json(resultado, ruta):
    datos = dict(resultado)
    datos["resumen"] = dict(resultado["resumen"])
    datos["resumen"]["por_severidad"] = dict(Counter(h["severidad"] for h in resultado["hallazgos"]))
    datos["resumen"]["por_microservicio"] = dict(Counter(h["microservicio"] for h in resultado["hallazgos"]))
    por_cat = Counter()
    for h in resultado["hallazgos"]:
        for c in h["owasp_top10"] + h["owasp_api"]:
            por_cat[c["codigo"]] += 1
        if not h["owasp_top10"] and not h["owasp_api"]:
            por_cat["pendiente de revisión"] += 1
    datos["resumen"]["por_categoria"] = dict(por_cat)
    Path(ruta).write_text(json.dumps(datos, indent=2, ensure_ascii=False), encoding="utf-8")
    return ruta


# ---------------------------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------------------------
CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--txt:#1d2430;--sub:#5b6475;--borde:#dfe3ea;--acento:#1f5fbf;--code:#f2f4f7;
--critica:#8e1b1b;--alta:#c2410c;--media:#a16207;--baja:#3f6212;--marca:#fff3bf}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--panel:#1b2029;--txt:#e6e9ef;--sub:#9aa3b2;--borde:#2c3340;
--acento:#7aa7f0;--code:#151a22;--critica:#f87171;--alta:#fb923c;--media:#facc15;--baja:#a3e635;--marca:#3b3315}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{padding:24px 32px;border-bottom:1px solid var(--borde);background:var(--panel)}
h1{margin:0 0 4px;font-size:22px}h2{font-size:17px;margin:28px 0 12px}.sub{color:var(--sub)}
main{max-width:1200px;margin:0 auto;padding:8px 32px 48px}
.tarjetas{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:20px}
.tarjeta{background:var(--panel);border:1px solid var(--borde);border-radius:8px;padding:14px 16px}
.tarjeta b{display:block;font-size:24px}.tarjeta span{color:var(--sub);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--borde);border-radius:8px;overflow:hidden}
th,td{padding:7px 10px;border-bottom:1px solid var(--borde);text-align:left;vertical-align:top}th{font-size:12px;color:var(--sub);font-weight:600}
td.n{text-align:center;font-variant-numeric:tabular-nums}td.cero{color:var(--borde)}.tabla-scroll{overflow-x:auto}
.filtros{display:flex;flex-wrap:wrap;gap:10px;margin:8px 0 16px}select,input{background:var(--panel);color:var(--txt);border:1px solid var(--borde);border-radius:6px;padding:6px 8px;font:inherit}
.hallazgo{background:var(--panel);border:1px solid var(--borde);border-left:4px solid var(--sub);border-radius:8px;padding:14px 18px;margin-bottom:12px}
.hallazgo[data-sev=Crítica]{border-left-color:var(--critica)}.hallazgo[data-sev=Alta]{border-left-color:var(--alta)}
.hallazgo[data-sev=Media]{border-left-color:var(--media)}.hallazgo[data-sev=Baja]{border-left-color:var(--baja)}
.cab{display:flex;flex-wrap:wrap;gap:8px;align-items:baseline;justify-content:space-between}.cab h3{margin:0;font-size:15px}
.chip{display:inline-block;border:1px solid var(--borde);border-radius:12px;padding:1px 9px;font-size:12px;margin:2px 4px 2px 0}
.chip.t10{border-color:var(--acento);color:var(--acento)}.sev{font-weight:700}.sev.Crítica{color:var(--critica)}.sev.Alta{color:var(--alta)}
.sev.Media{color:var(--media)}.sev.Baja{color:var(--baja)}
dl{display:grid;grid-template-columns:170px 1fr;gap:4px 12px;margin:10px 0}dt{color:var(--sub)}dd{margin:0}
pre{background:var(--code);border:1px solid var(--borde);border-radius:6px;padding:8px 0;overflow-x:auto;margin:6px 0;font-size:12.5px}
pre .l{display:block;padding:0 12px;white-space:pre}pre .l.r{background:var(--marca)}pre .num{color:var(--sub);display:inline-block;width:46px;user-select:none}
details summary{cursor:pointer;color:var(--acento)}.oculto{display:none}footer{color:var(--sub);font-size:12px;margin-top:32px}
"""

JS = """
const sel = id => document.getElementById(id);
function filtrar(){
  const s=sel('f-servicio').value, c=sel('f-categoria').value, v=sel('f-severidad').value, q=sel('f-texto').value.toLowerCase();
  let n=0;
  document.querySelectorAll('.hallazgo').forEach(h=>{
    const ok=(!s||h.dataset.servicio===s)&&(!c||h.dataset.categorias.split(' ').includes(c))&&(!v||h.dataset.sev===v)
      &&(!q||h.textContent.toLowerCase().includes(q));
    h.classList.toggle('oculto',!ok); if(ok) n++;
  });
  sel('contador').textContent=n+' hallazgos visibles';
}
['f-servicio','f-categoria','f-severidad','f-texto'].forEach(id=>sel(id).addEventListener('input',filtrar));
document.querySelectorAll('[data-filtro]').forEach(td=>td.addEventListener('click',()=>{
  const [s,c]=td.dataset.filtro.split('|'); sel('f-servicio').value=s; sel('f-categoria').value=c; filtrar();
  sel('lista').scrollIntoView({behavior:'smooth'});}));
filtrar();
"""


def _e(x):
    return html.escape(str(x), quote=True)


def _codigo(fragmento):
    filas = []
    for f in fragmento:
        clase = "l r" if f["resaltada"] else "l"
        filas.append(f'<span class="{clase}"><span class="num">{f["linea"]}</span>{_e(f["codigo"])}</span>')
    return "<pre>" + "".join(filas) + "</pre>"


def _hallazgo_html(h):
    cats = [c["codigo"] for c in h["owasp_top10"] + h["owasp_api"]] or ["pendiente"]
    chips = "".join(f'<span class="chip t10" title="{_e(c["nombre"])} (p={c["probabilidad"]})">{_e(c["codigo"])}</span>'
                    for c in h["owasp_top10"])
    chips += "".join(f'<span class="chip" title="{_e(c["nombre"])} (p={c["probabilidad"]})">{_e(c["codigo"])}</span>'
                     for c in h["owasp_api"])
    if not h["owasp_top10"] and not h["owasp_api"]:
        sug = h.get("categoria_sugerida") or {}
        chips = f'<span class="chip">Pendiente de revisión{" (sugerida: " + _e(sug.get("codigo")) + ")" if sug else ""}</span>'
    cwe = f'{_e(h["cwe"]["id"])} — {_e(h["cwe"]["nombre"])}' if h["cwe"] else "No determinado"
    indicadores = "".join(f'<li>Línea {i["linea"]}: {_e(i["descripcion"])} — <code>{_e(i["codigo"])}</code></li>'
                          for i in h["evidencia"]["indicadores"])
    influyentes = ", ".join(f'línea {x["linea"]} (−{x["aporte"]:.2f})' for x in h["evidencia"]["lineas_influyentes"]) or "—"
    t10_txt = ", ".join(f'{c["codigo"]} {c["nombre"]}' for c in h["owasp_top10"]) or "—"
    api_txt = ", ".join(f'{c["codigo"]} {c["nombre"]}' for c in h["owasp_api"]) or "No aplica / no determinada"
    return f"""
<article class="hallazgo" data-servicio="{_e(h['microservicio'])}" data-categorias="{_e(' '.join(cats))}" data-sev="{_e(h['severidad'])}">
 <div class="cab"><h3>{_e(h['id'])} · {_e(h['descripcion'])}</h3><span class="sev {_e(h['severidad'])}">{_e(h['severidad'])}</span></div>
 <div>{chips}</div>
 <dl>
  <dt>Microservicio</dt><dd>{_e(h['microservicio'])}</dd>
  <dt>Archivo</dt><dd><code>{_e(h['archivo'])}</code> · línea {h['linea']} (unidad <code>{_e(h['unidad'])}</code>, líneas {h['linea_inicio']}–{h['linea_fin']})</dd>
  <dt>OWASP Top 10:2025</dt><dd>{_e(t10_txt)}</dd>
  <dt>OWASP API 2023</dt><dd>{_e(api_txt)}</dd>
  <dt>CWE</dt><dd>{cwe}</dd>
  <dt>Confianza del modelo</dt><dd>{h['confianza']:.2f}</dd>
  <dt>Severidad estimada</dt><dd>{_e(h['severidad'])} — {_e(h['justificacion_severidad'])}</dd>
  <dt>Estado</dt><dd>{_e(h['estado'])}</dd>
  <dt>Recomendación</dt><dd>{_e(h['recomendacion'])}</dd>
 </dl>
 {_codigo(h['evidencia']['fragmento'])}
 <details><summary>Evidencia técnica</summary>
  <p><b>Líneas que más aportan a la predicción (oclusión):</b> {influyentes}</p>
  <p><b>Patrones combinados:</b> {_e(', '.join(h['evidencia']['patrones_combinados']) or '—')}</p>
  <ul>{indicadores or '<li>Sin indicadores de análisis estático: la decisión proviene de la representación TF-IDF.</li>'}</ul>
 </details>
</article>"""


def escribir_html(resultado, ruta):
    hs = resultado["hallazgos"]
    r = resultado["resumen"]
    sev = Counter(h["severidad"] for h in hs)
    servicios = [s["nombre"] for s in resultado["microservicios"]]
    categorias = [c for c in list(OWASP2025) + list(API2023) if c in resultado["categorias"]]
    matriz = defaultdict(Counter)
    for h in hs:
        cs = [c["codigo"] for c in h["owasp_top10"] + h["owasp_api"]] or ["pendiente"]
        for c in cs:
            matriz[h["microservicio"]][c] += 1
    columnas = categorias + (["pendiente"] if any(matriz[s]["pendiente"] for s in matriz) else [])
    cab = "".join(f'<th title="{_e(nombre_categoria(c))}">{_e(c.split(":")[0])}</th>' for c in columnas)
    filas = []
    for s in servicios:
        celdas = "".join(f'<td class="n{" cero" if not matriz[s][c] else ""}" data-filtro="{_e(s)}|{_e(c)}">{matriz[s][c] or "·"}</td>'
                         for c in columnas)
        filas.append(f"<tr><td>{_e(s)}</td>{celdas}<td class='n'><b>{sum(1 for h in hs if h['microservicio'] == s)}</b></td></tr>")
    tabla_servicios = "".join(
        f"<tr><td>{_e(s['nombre'])}</td><td><code>{_e(s['ruta'])}</code></td><td>{_e(', '.join(s['tecnologias']))}</td>"
        f"<td>{_e(', '.join(f'{k} ({v})' for k, v in s['lenguajes'].items()))}</td><td class='n'>{s['archivos_analizados']}</td>"
        f"<td>{_e(', '.join(f'{k} ({v})' for k, v in s['archivos_no_soportados'].items())) or '—'}</td></tr>"
        for s in resultado["microservicios"])
    tabla_cat = "".join(
        f"<tr><td>{_e(c)}</td><td>{_e(d['nombre'])}</td><td>{_e(d['estado'])}</td><td>{_e(d['motivo'])}</td>"
        f"<td class='n'>{sum(1 for h in hs if c in [x['codigo'] for x in h['owasp_top10'] + h['owasp_api']])}</td></tr>"
        for c, d in resultado["categorias"].items())
    opciones_s = "".join(f'<option value="{_e(s)}">{_e(s)}</option>' for s in servicios)
    opciones_c = "".join(f'<option value="{_e(c)}">{_e(c)} {_e(nombre_categoria(c))}</option>' for c in columnas if c != "pendiente")
    opciones_c += '<option value="pendiente">Pendiente de revisión</option>'
    opciones_v = "".join(f'<option value="{n}">{n}</option>' for n in reversed(NIVELES))
    modelo = resultado["modelo"]
    pagina = f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>vulnminer · {_e(resultado['proyecto'])}</title><style>{CSS}</style></head>
<body><header><h1>Reporte de seguridad · {_e(resultado['proyecto'])}</h1>
<div class="sub">vulnminer {_e(resultado['version'])} · {_e(resultado['fecha'])} · Estándares: OWASP Top 10:2025, OWASP API Security Top 10:2023 ·
Modelo: {_e(modelo.get('detector'))} (umbral {modelo.get('umbral')}){' + combinación con la evidencia estática' if modelo.get('combinacion') else ''}</div>
<div class="tarjetas">
 <div class="tarjeta"><span>Microservicios</span><b>{r['microservicios']}</b></div>
 <div class="tarjeta"><span>Archivos analizados</span><b>{r['archivos_analizados']}</b></div>
 <div class="tarjeta"><span>Unidades analizadas</span><b>{r['unidades_analizadas']}</b></div>
 <div class="tarjeta"><span>Hallazgos potenciales</span><b>{r['hallazgos']}</b></div>
 {''.join(f'<div class="tarjeta"><span>{n}</span><b class="sev {n}">{sev.get(n, 0)}</b></div>' for n in reversed(NIVELES))}
</div></header>
<main>
<p class="sub">Los hallazgos son <b>potenciales</b>: los produce un modelo de minería de datos sobre el código y la configuración, y
deben verificarse. La confianza del modelo no equivale a la severidad.</p>
<h2>Hallazgos por microservicio y categoría</h2>
<div class="tabla-scroll"><table><thead><tr><th>Microservicio</th>{cab}<th>Total</th></tr></thead><tbody>{''.join(filas)}</tbody></table></div>
<p class="sub">Haga clic en una celda para filtrar la lista.</p>
<h2 id="lista">Hallazgos</h2>
<div class="filtros">
 <select id="f-servicio"><option value="">Todos los microservicios</option>{opciones_s}</select>
 <select id="f-categoria"><option value="">Todas las categorías</option>{opciones_c}</select>
 <select id="f-severidad"><option value="">Todas las severidades</option>{opciones_v}</select>
 <input id="f-texto" type="search" placeholder="Buscar texto…"><span id="contador" class="sub"></span>
</div>
{''.join(_hallazgo_html(h) for h in hs) or '<p>No se detectaron hallazgos.</p>'}
<h2>Microservicios identificados</h2>
<div class="tabla-scroll"><table><thead><tr><th>Nombre</th><th>Ruta</th><th>Tecnologías</th><th>Lenguajes (archivos)</th><th>Archivos</th><th>No soportados</th></tr></thead>
<tbody>{tabla_servicios}</tbody></table></div>
<h2>Categorías evaluadas</h2>
<div class="tabla-scroll"><table><thead><tr><th>Código</th><th>Categoría</th><th>Estado</th><th>Motivo</th><th>Hallazgos</th></tr></thead>
<tbody>{tabla_cat}</tbody></table></div>
<footer>Generado por vulnminer en {r['duracion_segundos']} s. Ruta analizada: {_e(resultado['ruta'])}</footer>
</main><script>{JS}</script></body></html>"""
    Path(ruta).write_text(pagina, encoding="utf-8")
    return ruta

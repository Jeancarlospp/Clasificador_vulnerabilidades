"""Pruebas de los indicadores de análisis estático (características del modelo)."""

import numpy as np
import pytest

from vulnminer import caracteristicas as C
from vulnminer.segmentacion import Unidad


def unidad(texto, lenguaje="python", subtipo="codigo", contexto=""):
    return Unidad("a", lenguaje, subtipo, "f", list(range(1, len(texto.splitlines()) + 1)), texto, contexto)


def activos(texto, **kw):
    v = C.vector(unidad(texto, **kw))
    return {n for n, x in zip(C.nombres_caracteristicas(), v) if x > 0 and not n.startswith(("m_", "sub_", "len_"))}


def test_dimension_constante():
    assert len(C.vector(unidad("x = 1"))) == len(C.nombres_caracteristicas())
    assert len(set(C.nombres_caracteristicas())) == len(C.nombres_caracteristicas())


@pytest.mark.parametrize("codigo,indicador", [
    ("cursor.execute(\"SELECT * FROM users WHERE id = \" + uid)", "sql_dinamico"),
    ("db.query(`SELECT * FROM t WHERE name = '${name}'`)", "sql_dinamico"),
    ("cur.execute(f\"DELETE FROM t WHERE id = {x}\")", "sql_dinamico"),
    ("ps = conn.prepareStatement(\"SELECT * FROM t WHERE id = ?\");", "sql_parametrizado"),
    ("os.system('ping ' + host)", "ejecucion_comando"),
    ("subprocess.run(cmd, shell=True)", "shell_activado"),
    ("data = pickle.loads(request.data)", "deserializacion"),
    ("requests.get(url, verify=False)", "tls_sin_verificar"),
    ("payload = jwt.decode(token, options={'verify_signature': False})", "jwt_inseguro"),
    ("JWT_SECRET = 'super-secret-123'", "secreto_literal"),
    ("spring.datasource.password=admin123", "secreto_literal"),
    ("JWT_SECRET=abc123xyz", "secreto_literal"),
    ("    password: S3cr3tPass", "secreto_literal"),
    ("const apiKey = 'AKIAABCDEFGHIJKLMNOP';", "secreto_literal"),
    ("app.run(host='0.0.0.0', debug=True)", "debug_activo"),
    ("app.use(cors({ origin: '*' }))", "cors_permisivo"),
    ("http.csrf().disable();", "csrf_desactivado"),
    ("Object.assign(user, req.body);", "asignacion_masiva"),
    ("hashlib.md5(password.encode())", "hash_debil"),
    ("token = Math.random().toString(36)", "aleatorio_debil"),
    ("catch (Exception e) { e.printStackTrace(); }", "error_expuesto"),
    ("except Exception:\n    pass", "excepcion_silenciada"),
    ("@UseGuards(JwtAuthGuard)", "guard_autenticacion"),
    ("@PreAuthorize(\"hasRole('ADMIN')\")", "verificacion_rol"),
    ("if order.user_id != current_user.id: abort(403)", "verificacion_propiedad"),
    ("const limiter = rateLimit({ windowMs: 60000, max: 5 });", "limite_frecuencia"),
    ("management.endpoints.web.exposure.include=*", "actuator_expuesto"),
    ("FROM node:latest", "imagen_sin_version"),
    ("    privileged: true", "contenedor_root"),
    ("RUN curl -sSL https://x.sh | bash", "descarga_remota"),
])
def test_indicadores_reconocen_patrones(codigo, indicador):
    assert indicador in activos(codigo)


@pytest.mark.parametrize("codigo,indicador", [
    ("cursor.execute(\"SELECT * FROM users WHERE id = %s\", (uid,))", "sql_dinamico"),
    ("subprocess.run(['ping', '-c', '1', host])", "shell_activado"),
    ("data = yaml.safe_load(texto)", "deserializacion"),
    ("JWT_SECRET = os.environ['JWT_SECRET']", "secreto_literal"),
    ("const secret = process.env.JWT_SECRET;", "secreto_literal"),
    ("spring.datasource.password=${DB_PASSWORD}", "secreto_literal"),
    ("FROM node:20.11-alpine", "imagen_sin_version"),
    ("app.use(cors({ origin: ['https://app.example.com'] }))", "cors_permisivo"),
])
def test_indicadores_no_disparan_en_codigo_seguro(codigo, indicador):
    assert indicador not in activos(codigo)


def test_interaccion_entrada_y_operacion_peligrosa():
    codigo = "q = request.args.get('q')\ncursor.execute(\"SELECT * FROM t WHERE n = '\" + q + \"'\")"
    assert "x_entrada_sql" in activos(codigo)


def test_bola_y_su_correccion():
    vulnerable = "@app.get('/orders/<int:order_id>')\ndef get_order(order_id):\n    o = Order.query.get(order_id)\n    return jsonify(o.to_dict())"
    seguro = ("@app.get('/orders/<int:order_id>')\n@login_required\ndef get_order(order_id):\n    o = Order.query.get(order_id)\n"
              "    if o.user_id != current_user.id:\n        abort(403)\n    return jsonify(o.to_dict())")
    assert "x_id_ruta_sin_propiedad" in activos(vulnerable)
    assert "x_id_ruta_sin_propiedad" not in activos(seguro)


def test_guard_en_contexto_de_clase():
    codigo = "@Get(':id')\nfindOne(@Param('id') id: string) { return this.s.findOne(id); }"
    sin = activos(codigo, lenguaje="typescript")
    con = activos(codigo, lenguaje="typescript", contexto="@UseGuards(JwtAuthGuard)\nexport class C")
    assert "x_ruta_sin_autenticacion" in sin
    assert "x_ruta_sin_autenticacion" not in con and "ctx_guard_autenticacion" in con


def test_evidencias_con_linea():
    u = Unidad("a.py", "python", "codigo", "f", [10, 11, 12], "def f():\n    x = 1\n    os.system('rm ' + x)")
    ev = C.evidencias(u)
    assert ("ejecucion_comando", 12, "os.system('rm ' + x)") in ev


def test_valores_finitos():
    v = C.vector(unidad("x" * 5000))
    assert np.all(np.isfinite(v))


@pytest.mark.parametrize("codigo,lenguaje", [
    ("@Get(':id')\nfindOne(@Param('id') id: string) { return this.orders.findById(id); }", "typescript"),
    ("@GetMapping(\"/{id}\")\npublic Order get(@PathVariable Long id) { return orderRepository.findById(id); }", "java"),
    ("def get(self, request, order_id=None):\n    order = Order.objects.get(id=order_id)\n    return Response(order)", "python"),
])
def test_bola_en_nest_spring_y_django(codigo, lenguaje):
    a = activos(codigo, lenguaje=lenguaje)
    assert "parametro_ruta_id" in a and "x_recurso_propio_sin_propiedad" in a


def test_cors_de_la_clase_no_es_contexto():
    assert "cors_permisivo" not in C.CONTEXTO


def test_aleatorio_debil_solo_es_sensible_con_secretos():
    assert "x_aleatorio_sensible" in activos("token = str(random.randint(0, 999999))")
    assert "x_aleatorio_sensible" not in activos("producto = random.choice(productos)")


def test_variantes_de_vector_mantienen_dimension():
    u = unidad("cursor.execute('SELECT * FROM t WHERE a = ' + x)\ncursor.execute('SELECT * FROM t WHERE b = ' + y)")
    base, binario, sin_estilo = C.vector(u), C.vector(u, binario=True), C.vector(u, estilo=False)
    assert len(base) == len(binario) == len(sin_estilo)
    i = C.nombres_caracteristicas().index("sql_dinamico")
    assert binario[i] == 1.0 and base[i] > 1.0
    j = C.nombres_caracteristicas().index("m_llamadas")
    assert sin_estilo[j] == 0.0 and base[j] > 0


def test_escuchar_en_todas_las_interfaces_no_es_puerto_sensible():
    assert "puerto_sensible" not in activos("uvicorn.run(app, host='0.0.0.0', port=8000)")
    assert "puerto_sensible" in activos('    ports:\n      - "5432:5432"', lenguaje="config", subtipo="compose")


def test_object_assign_con_cuerpo_generico():
    assert "asignacion_masiva" in activos("Object.assign(user, body);", lenguaje="typescript")

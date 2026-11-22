"""Pruebas del segmentador de archivos en unidades de análisis."""

from vulnminer.segmentacion import segmentar, tipo_archivo

JAVA = '''package demo;

@RestController
@RequestMapping("/api/orders")
public class OrderController {
    private final OrderRepository repo;

    /** Devuelve un pedido. */
    @GetMapping("/{id}")
    public Order get(@PathVariable Long id) {
        return repo.findById(id).orElseThrow();
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public void delete(@PathVariable Long id) {
        if (id > 0) {
            repo.deleteById(id);
        }
    }
}
'''

EXPRESS = '''const router = require('express').Router();
router.use(auth);

router.get('/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user);
});

module.exports = router;
'''

NEST = '''@Controller('cats')
@UseGuards(JwtAuthGuard)
export class CatsController {
  constructor(private readonly service: CatsService) {}

  @Get(':id')
  findOne(@Param('id') id: string): Promise<Cat> {
    return this.service.findOne(+id);
  }
}
'''

PY = '''from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/items/{item_id}")
async def read_item(item_id: int, user=Depends(get_current_user)):
    item = db.get(item_id)
    return item

class ItemIn(BaseModel):
    name: str
    price: float
'''


def _por_nombre(unidades):
    return {u.nombre: u for u in unidades}


def test_java_metodos_con_anotaciones_y_lineas_correctas():
    u = _por_nombre(segmentar("OrderController.java", JAVA))
    assert {"get", "delete"} <= set(u)
    get = u["get"]
    assert get.linea_inicio == 9 and get.linea_fin == 12          # desde la anotación hasta la llave de cierre
    assert get.texto.splitlines()[0].strip() == '@GetMapping("/{id}")'
    assert "@RequestMapping" in get.contexto                        # la cabecera de la clase da contexto
    assert "@PreAuthorize" in u["delete"].texto


def test_express_handler_incluye_registro_de_ruta():
    u = _por_nombre(segmentar("users.js", EXPRESS))
    assert "GET /users/:id" in u
    h = u["GET /users/:id"]
    assert h.linea_inicio == 4 and "router.get('/users/:id'" in h.texto
    assert "router.use(auth)" in h.contexto


def test_nestjs_guard_de_clase_en_contexto():
    u = _por_nombre(segmentar("cats.controller.ts", NEST))
    assert "findOne" in u
    assert u["findOne"].linea_inicio == 6 and "@Get(':id')" in u["findOne"].texto
    assert "@UseGuards(JwtAuthGuard)" in u["findOne"].contexto


def test_python_funciones_decoradas_y_clases():
    u = _por_nombre(segmentar("items.py", PY))
    assert u["read_item"].linea_inicio == 4 and "@router.get" in u["read_item"].texto
    assert "clase ItemIn" in u


def test_lineas_de_unidad_coinciden_con_el_archivo():
    for nombre, texto in [("a.java", JAVA), ("a.js", EXPRESS), ("a.ts", NEST), ("a.py", PY)]:
        lineas = texto.splitlines()
        for un in segmentar(nombre, texto):
            for n, contenido in zip(un.lineas, un.texto.splitlines()):
                assert lineas[n - 1] == contenido, (nombre, un.nombre, n)


def test_funcion_larga_se_divide_en_ventanas_con_cabecera():
    cuerpo = "\n".join(f"    x{i} = {i}" for i in range(150))
    unidades = segmentar("largo.py", "def enorme():\n" + cuerpo + "\n")
    assert len(unidades) >= 3
    assert all(u.texto.startswith("def enorme") for u in unidades)


def test_tipos_de_archivo():
    assert tipo_archivo("x/Dockerfile", "") == ("config", "dockerfile")
    assert tipo_archivo("docker-compose.yml", "services:\n  a:\n    image: x") == ("config", "compose")
    assert tipo_archivo("src/main/resources/application.yml", "spring:\n") == ("config", "yaml")
    assert tipo_archivo("application.properties", "") == ("config", "properties")
    assert tipo_archivo("api.yaml", "openapi: 3.0.0\n") == ("config", "openapi")
    assert tipo_archivo("package.json", "{}") == ("config", "manifiesto")
    assert tipo_archivo("requirements.txt", "") == ("config", "manifiesto")
    assert tipo_archivo("main.ts", "") == ("typescript", "codigo")
    assert tipo_archivo("README.md", "") is None
    assert tipo_archivo("datos.json", "{}") is None


def test_compose_por_servicio_y_dockerfile_por_etapa():
    compose = "version: '3'\nservices:\n  api:\n    image: api:1.0\n    ports:\n      - '8080:8080'\n  db:\n    image: postgres\n"
    u = segmentar("docker-compose.yml", compose)
    assert [x.nombre for x in u if x.nombre.startswith("servicio")] == ["servicio api", "servicio db"]
    assert u[-1].linea_inicio == 7
    docker = "FROM node:18 AS build\nRUN npm ci\nFROM nginx:1.25\nCOPY --from=build /app /usr/share\n"
    etapas = segmentar("Dockerfile", docker)
    assert len(etapas) == 2 and etapas[1].linea_inicio == 3


def test_openapi_por_ruta():
    spec = "openapi: 3.0.0\ninfo:\n  title: t\npaths:\n  /users/{id}:\n    get:\n      summary: x\n  /admin:\n    delete:\n      summary: y\n"
    nombres = [u.nombre for u in segmentar("api.yaml", spec)]
    assert "ruta /users/{id}" in nombres and "ruta /admin" in nombres


def test_properties_agrupa_por_prefijo():
    props = "spring.datasource.url=jdbc:x\nspring.datasource.password=123\n\nmanagement.endpoints.web.exposure.include=*\n"
    unidades = segmentar("application.properties", props)
    assert any("spring.datasource.password" in u.texto for u in unidades)
    assert any("management" in u.texto for u in unidades)


def test_archivo_vacio_o_invalido_no_falla():
    assert segmentar("a.py", "") == []
    assert segmentar("a.py", "def roto(:\n  pass") is not None
    assert segmentar("a.java", "}}}{{{") is not None


def test_handlers_anidados_registrados_dentro_de_una_funcion():
    codigo = ("def init(app):\n\n    @app.route('/a', methods=['GET'])\n    def a_get():\n        return 'x'\n\n"
              "    @app.route('/a', methods=['POST'])\n    def a_post():\n        return request.form['x']\n")
    nombres = {u.nombre for u in segmentar("h.py", codigo)}
    assert {"a_get", "a_post"} <= nombres and "init" not in nombres


def test_metodos_de_objeto_literal_no_comparten_lineas():
    codigo = ("module.exports = {\n  save: async (req, res) => {\n    a();\n  },\n\n  get: async (req, res) => {\n"
              "    b();\n  },\n};\n")
    u = {x.nombre: x for x in segmentar("c.js", codigo)}
    assert u["save"].linea_fin == 4 and u["get"].linea_inicio == 6

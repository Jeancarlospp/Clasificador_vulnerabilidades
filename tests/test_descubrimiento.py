"""Pruebas del descubrimiento de microservicios (RF06)."""

from vulnminer.descubrimiento import RAIZ_PROYECTO, descubrir


def test_identifica_microservicios_con_nombres_de_compose(proyecto):
    servicios, total = descubrir(proyecto)
    nombres = {s.nombre for s in servicios}
    assert {"users", "products", "orders", RAIZ_PROYECTO} == nombres
    assert total == sum(len(s.archivos) for s in servicios)


def test_tecnologias_detectadas(proyecto):
    servicios = {s.nombre: s for s in descubrir(proyecto)[0]}
    assert "NestJS" in servicios["users"].tecnologias and "Express" not in servicios["users"].tecnologias
    assert "Spring Boot" in servicios["products"].tecnologias and "Docker" in servicios["products"].tecnologias
    assert "FastAPI" in servicios["orders"].tecnologias


def test_asigna_archivos_y_excluye_dependencias_y_pruebas(proyecto):
    servicios = {s.nombre: s for s in descubrir(proyecto)[0]}
    todos = [a for s in servicios.values() for a in s.archivos]
    assert "docker-compose.yml" in servicios[RAIZ_PROYECTO].archivos
    assert "product-service/src/main/resources/application.properties" in servicios["products"].archivos
    assert not any("node_modules" in a for a in todos)
    assert not any(a.endswith(".spec.ts") or "src/test" in a for a in todos)
    assert "README.md" not in todos


def test_incluir_pruebas(proyecto):
    todos = [a for s in descubrir(proyecto, incluir_pruebas=True)[0] for a in s.archivos]
    assert any("src/test" in a for a in todos) and any(a.endswith(".spec.ts") for a in todos)


def test_proyecto_sin_servicios_es_un_solo_servicio(tmp_path):
    (tmp_path / "app.py").write_text("print('hola')\n")
    servicios, total = descubrir(tmp_path)
    assert len(servicios) == 1 and servicios[0].ruta == "." and total == 1


def test_lenguajes_no_soportados_se_informan(tmp_path):
    (tmp_path / "svc").mkdir()
    (tmp_path / "svc" / "go.mod").write_text("module x\n")
    (tmp_path / "svc" / "main.go").write_text("package main\n")
    servicios, _ = descubrir(tmp_path)
    assert servicios[0].no_soportados == {".go": 1}


def test_es_binario():
    from vulnminer.descubrimiento import es_binario
    assert es_binario(b"\x89PNG\r\n\x1a\n\x00\x00")
    assert not es_binario("const nombre = 'añadir ñandú';".encode())
    assert not es_binario(b"")

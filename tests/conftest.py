"""Proyecto de microservicios mínimo para las pruebas de descubrimiento, análisis y CLI."""

from pathlib import Path

import pytest

ARCHIVOS = {
    "docker-compose.yml": """services:
  users:
    build: ./user-service
    ports:
      - "3000:3000"
  products:
    build: ./product-service
  orders:
    build: ./order-service
    environment:
      - DB_PASSWORD=supersecret123
""",
    "user-service/package.json": '{"name": "user-service", "dependencies": {"@nestjs/core": "10.0.0", "express": "4.18.2"}}',
    "user-service/src/users/users.controller.ts": """import { Controller, Get, Param, UseGuards } from '@nestjs/common';

@Controller('users')
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.users.findById(id);
  }
}
""",
    "user-service/src/users/users.controller.spec.ts": "describe('x', () => { it('y', () => {}); });\n",
    "user-service/node_modules/lib/index.js": "module.exports = eval(process.argv[2]);\n",
    "product-service/pom.xml": "<project><dependencies><dependency><artifactId>spring-boot-starter-web</artifactId></dependency></dependencies></project>",
    "product-service/Dockerfile": "FROM openjdk:latest\nCOPY target/app.jar /app.jar\nCMD [\"java\", \"-jar\", \"/app.jar\"]\n",
    "product-service/src/main/java/demo/ProductController.java": """package demo;

@RestController
public class ProductController {
    @GetMapping("/search")
    public List<Product> search(@RequestParam String q) {
        String sql = "SELECT * FROM products WHERE name = '" + q + "'";
        return jdbc.query(sql, mapper);
    }
}
""",
    "product-service/src/main/resources/application.properties": "management.endpoints.web.exposure.include=*\nspring.datasource.password=root123\n",
    "product-service/src/test/java/demo/ProductControllerTest.java": "class ProductControllerTest {}\n",
    "order-service/requirements.txt": "fastapi\nrequests\n",
    "order-service/app/main.py": """from fastapi import FastAPI
import requests

app = FastAPI()


@app.get("/fetch")
def fetch(url: str):
    return requests.get(url, verify=False).text
""",
    "README.md": "# demo\n",
}


@pytest.fixture(scope="session")
def proyecto(tmp_path_factory):
    raiz = tmp_path_factory.mktemp("proyecto-microservicios")
    for rel, contenido in ARCHIVOS.items():
        p = raiz / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(contenido)
    return raiz


@pytest.fixture(scope="session")
def ruta_modelo():
    ruta = Path(__file__).resolve().parents[1] / "vulnminer" / "modelos" / "vulnminer.joblib"
    if not ruta.exists():
        pytest.skip("modelo no entrenado: ejecute scripts/entrenar.py")
    return ruta

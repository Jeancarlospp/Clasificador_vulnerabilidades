"""Pruebas del catálogo OWASP y de la tabla de correspondencias CWE."""

from vulnminer import catalogo as c


def test_veinte_categorias_con_identificadores_oficiales():
    assert len(c.OWASP2025) == 10 and len(c.API2023) == 10
    assert list(c.OWASP2025) == [f"A{i:02d}:2025" for i in range(1, 11)]
    assert list(c.API2023) == [f"API{i}:2023" for i in range(1, 11)]
    assert set(c.RECOMENDACION_CATEGORIA) == set(c.CATEGORIAS)


def test_relaciones_oficiales_top10():
    assert c.cwe_a_owasp2025("CWE-89") == "A05:2025"
    assert c.cwe_a_owasp2025(79) == "A05:2025"
    assert c.cwe_a_owasp2025("CWE-639") == "A01:2025"
    assert c.cwe_a_owasp2025("CWE-918") == "A01:2025"
    assert c.cwe_a_owasp2025("CWE-798") == "A07:2025"
    assert c.cwe_a_owasp2025("CWE-502") == "A08:2025"
    assert c.cwe_a_owasp2025("CWE-1104") == "A03:2025"
    assert c.cwe_a_owasp2025("CWE-209") == "A10:2025"


def test_relaciones_oficiales_api2023():
    assert c.cwe_a_api2023("CWE-639") == ["API1:2023"]
    assert set(c.cwe_a_api2023("CWE-285")) == {"API1:2023", "API5:2023"}
    assert c.cwe_a_api2023("CWE-918") == ["API7:2023"]
    assert "API4:2023" in c.cwe_a_api2023("CWE-770")
    assert "API8:2023" in c.cwe_a_api2023("CWE-942")
    assert c.cwe_a_api2023("CWE-1059") == ["API9:2023"]


def test_relaciones_extendidas_y_de_contexto():
    assert c.cwe_a_owasp2025("CWE-943") == "A05:2025"          # NoSQL -> padre CWE-74
    assert c.cwe_a_owasp2025("CWE-770") == "A06:2025"
    assert c.cwe_a_api2023("CWE-862") == ["API5:2023"]
    # CWE-20/200 solo pertenecen a API10 cuando el fragmento consume otra API
    assert "API10:2023" not in c.cwe_a_api2023("CWE-20")
    assert "API10:2023" in c.cwe_a_api2023("CWE-20", consume_api=True)
    assert "API10:2023" in c.cwe_a_api2023("CWE-295", consume_api=True)


def test_inyeccion_sql_no_tiene_categoria_api():
    assert c.cwe_a_api2023("CWE-89") == []


def test_cwe_desconocido_o_invalido():
    assert c.cwe_a_owasp2025("CWE-99999") is None
    assert c.cwe_a_owasp2025("texto") is None
    assert c.cwe_a_api2023(None) == []


def test_nombres_y_conocimiento():
    assert c.nombre_cwe("CWE-89").startswith("Improper Neutralization")
    problema, recomendacion, severidad = c.conocimiento("CWE-639")
    assert problema and recomendacion and severidad in {"Crítica", "Alta", "Media", "Baja"}
    for n, (_, _, sev) in c.CONOCIMIENTO.items():
        assert sev in {"Crítica", "Alta", "Media", "Baja"}, n
        assert c.cwe_a_owasp2025(n) is not None, f"CWE-{n} sin categoría Top 10"


def test_descripciones_completas():
    from vulnminer.caracteristicas import NOMBRES_DERIVADAS
    assert set(c.DESCRIPCION_CATEGORIA) == set(c.CATEGORIAS)
    assert set(c.DESCRIPCION_PATRON) <= set(NOMBRES_DERIVADAS)

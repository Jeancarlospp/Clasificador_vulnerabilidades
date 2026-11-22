"""Pruebas del preprocesamiento léxico (limpieza anti-fuga y tokenización)."""

from vulnminer.lexico import limpiar_codigo, neutralizar_identificadores, preparar, tokenizar


def test_elimina_comentarios_que_delatan_la_etiqueta():
    codigo = "# ruleid: sql-injection\ncursor.execute(q + x)\n// ok: rule\nfoo()  # BAD\nbar()  // vulnerable here"
    limpio = limpiar_codigo(codigo)
    assert "ruleid" not in limpio and "ok:" not in limpio
    assert "BAD" not in limpio and "vulnerable" not in limpio
    assert "cursor.execute(q + x)" in limpio and "foo()" in limpio and "bar()" in limpio


def test_conserva_comentarios_normales():
    assert "# calcula el total" in limpiar_codigo("# calcula el total\nx = 1")


def test_neutraliza_nombres_que_delatan():
    texto = neutralizar_identificadores("def bad1(): pass\nfunction goodG2B() {}\nBenchmarkTest00042\nunsafe_query = 1")
    assert "bad1" not in texto and "goodG2B" not in texto and "unsafe_query" not in texto
    assert "BenchmarkTest" not in texto


def test_respeta_apis_reales():
    texto = neutralizar_identificadores("yaml.safe_load(x); secure_filename(f); new SecureRandom()")
    assert "safe_load" in texto and "secure_filename" in texto and "SecureRandom" in texto


def test_tokenizador_de_codigo():
    tokens = tokenizar('query = "SELECT * FROM t WHERE id=" + userId; `${a}`')
    assert "userid" in tokens and "user" in tokens and "id" in tokens
    assert "+" in tokens and "${" in tokens


def test_preparar_es_idempotente():
    codigo = "x = request.args.get('id')\ncursor.execute('SELECT ' + x)"
    assert preparar(preparar(codigo)) == preparar(codigo)

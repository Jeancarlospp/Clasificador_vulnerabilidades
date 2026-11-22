"""Catálogo de las 20 categorías OWASP y base de conocimiento por CWE.

- OWASP Top 10:2025 (A01..A10) y OWASP API Security Top 10:2023 (API1..API10) con sus
  identificadores oficiales.
- Correspondencias CWE -> categoría (oficiales y extendidas) en ``datos/mapeo_cwe.json``,
  generadas por ``scripts/construir_mapeo_cwe.py`` a partir de los documentos oficiales.
- Para cada CWE frecuente: descripción del problema, recomendación de remediación y
  severidad base (la severidad se ajusta después según el contexto; ver ``severidad.py``).
"""

import json
from functools import lru_cache
from pathlib import Path

DATOS = Path(__file__).with_name("datos")

OWASP2025 = {
    "A01:2025": ("Pérdida de control de acceso", "Broken Access Control"),
    "A02:2025": ("Configuración de seguridad incorrecta", "Security Misconfiguration"),
    "A03:2025": ("Fallas en la cadena de suministro de software", "Software Supply Chain Failures"),
    "A04:2025": ("Fallas criptográficas", "Cryptographic Failures"),
    "A05:2025": ("Inyección", "Injection"),
    "A06:2025": ("Diseño inseguro", "Insecure Design"),
    "A07:2025": ("Fallas de autenticación", "Authentication Failures"),
    "A08:2025": ("Fallas en la integridad del software o de los datos", "Software or Data Integrity Failures"),
    "A09:2025": ("Fallas en el registro, alerta y monitoreo de seguridad", "Security Logging and Alerting Failures"),
    "A10:2025": ("Manejo inadecuado de condiciones excepcionales", "Mishandling of Exceptional Conditions"),
}

API2023 = {
    "API1:2023": ("Autorización incorrecta a nivel de objeto", "Broken Object Level Authorization"),
    "API2:2023": ("Autenticación incorrecta", "Broken Authentication"),
    "API3:2023": ("Autorización incorrecta a nivel de propiedades del objeto", "Broken Object Property Level Authorization"),
    "API4:2023": ("Consumo ilimitado de recursos", "Unrestricted Resource Consumption"),
    "API5:2023": ("Autorización incorrecta a nivel de función", "Broken Function Level Authorization"),
    "API6:2023": ("Acceso ilimitado a flujos de negocio sensibles", "Unrestricted Access to Sensitive Business Flows"),
    "API7:2023": ("Falsificación de solicitudes del lado del servidor", "Server Side Request Forgery"),
    "API8:2023": ("Configuración de seguridad incorrecta", "Security Misconfiguration"),
    "API9:2023": ("Gestión inadecuada del inventario de API", "Improper Inventory Management"),
    "API10:2023": ("Consumo inseguro de API", "Unsafe Consumption of APIs"),
}

CATEGORIAS = {**OWASP2025, **API2023}
ESTANDARES = {"owasp2025": list(OWASP2025), "api2023": list(API2023)}

# Recomendación general por categoría (se usa cuando el CWE no está en la base de conocimiento).
RECOMENDACION_CATEGORIA = {
    "A01:2025": "Aplicar control de acceso en el servidor con denegación por defecto y verificar que el usuario autenticado tenga permiso sobre el recurso solicitado.",
    "A02:2025": "Endurecer la configuración: desactivar funciones de depuración y endpoints innecesarios, restringir CORS y aplicar valores seguros por defecto en cada entorno.",
    "A03:2025": "Fijar versiones de dependencias e imágenes base, usar fuentes confiables con verificación de integridad y revisar periódicamente las vulnerabilidades conocidas (SCA).",
    "A04:2025": "Usar algoritmos criptográficos vigentes (AES-GCM, SHA-256+, bcrypt/argon2), claves gestionadas fuera del código y TLS en todas las comunicaciones.",
    "A05:2025": "Separar datos y comandos: consultas parametrizadas, APIs que no invoquen intérpretes y validación/escape de la entrada según el contexto.",
    "A06:2025": "Incorporar controles de diseño: límites de recursos, validaciones de negocio en el servidor y modelado de amenazas de los flujos críticos.",
    "A07:2025": "Usar mecanismos de autenticación probados, proteger y rotar los secretos, limitar intentos y validar firma y expiración de los tokens.",
    "A08:2025": "Verificar la integridad de datos y componentes (firmas, listas blancas de clases), y no deserializar ni asignar masivamente datos no confiables.",
    "A09:2025": "Registrar eventos de seguridad sin datos sensibles, neutralizar la entrada antes de escribirla en los logs y configurar alertas.",
    "A10:2025": "Manejar las excepciones de forma específica, fallar de forma cerrada (denegar) y no exponer detalles internos en las respuestas.",
    "API1:2023": "Verificar en cada endpoint que el objeto solicitado (por su id) pertenezca al usuario autenticado o que este tenga permiso explícito sobre él.",
    "API2:2023": "Proteger la autenticación: validar firma y expiración de los JWT, usar secretos robustos fuera del código y limitar intentos de inicio de sesión.",
    "API3:2023": "Definir explícitamente las propiedades que se pueden leer y modificar (DTO/esquemas) y no devolver ni aceptar objetos completos.",
    "API4:2023": "Limitar la frecuencia de peticiones, el tamaño de las cargas y la paginación de las consultas; establecer tiempos de espera.",
    "API5:2023": "Restringir las funciones administrativas por rol en el servidor (guards, @PreAuthorize, dependencias de seguridad) con denegación por defecto.",
    "API6:2023": "Identificar los flujos de negocio sensibles y protegerlos contra el uso automatizado (límites por usuario, CAPTCHA, detección de bots).",
    "API7:2023": "No construir URLs a partir de la entrada del usuario; usar listas blancas de destinos y bloquear direcciones internas.",
    "API8:2023": "Endurecer la configuración de la API: CORS restrictivo, sin trazas de error, cabeceras de seguridad, TLS y sin funciones de depuración.",
    "API9:2023": "Mantener un inventario actualizado de endpoints y versiones, retirar versiones antiguas y no exponer documentación en producción.",
    "API10:2023": "Tratar las respuestas de otras APIs como no confiables: validar su contenido, exigir TLS con verificación de certificados y fijar tiempos de espera.",
}

# Descripción breve del problema por categoría (cuando no se determina el CWE).
DESCRIPCION_CATEGORIA = {
    "A01:2025": "Posible falla de control de acceso: la operación no verifica suficientemente quién puede realizarla.",
    "A02:2025": "Posible configuración de seguridad incorrecta o insegura por defecto.",
    "A03:2025": "Posible riesgo en la cadena de suministro: componentes o imágenes sin versión fijada o de origen no verificado.",
    "A04:2025": "Posible falla criptográfica: algoritmo débil, secreto expuesto o comunicación sin cifrar.",
    "A05:2025": "Posible inyección: datos variables llegan a un intérprete (SQL, comandos, plantillas, consultas).",
    "A06:2025": "Posible diseño inseguro: faltan límites o controles de negocio en la operación.",
    "A07:2025": "Posible falla de autenticación: credenciales, tokens o intentos de acceso sin la protección adecuada.",
    "A08:2025": "Posible falla de integridad: datos u objetos no confiables se deserializan o asignan sin control.",
    "A09:2025": "Posible falla de registro: eventos sensibles se registran de forma insegura o no se registran.",
    "A10:2025": "Posible manejo inadecuado de excepciones: errores silenciados, expuestos al cliente o que fallan de forma abierta.",
    "API1:2023": "Posible autorización incorrecta a nivel de objeto (BOLA): se accede a un objeto por su identificador sin comprobar su propietario.",
    "API2:2023": "Posible autenticación incorrecta en la API (tokens, credenciales o intentos sin protección).",
    "API3:2023": "Posible autorización incorrecta a nivel de propiedades: se exponen o aceptan propiedades del objeto sin filtrar.",
    "API4:2023": "Posible consumo ilimitado de recursos: faltan límites de frecuencia, tamaño o paginación.",
    "API5:2023": "Posible autorización incorrecta a nivel de función: una operación privilegiada no comprueba el rol.",
    "API6:2023": "Posible acceso ilimitado a un flujo de negocio sensible.",
    "API7:2023": "Posible SSRF: el servidor realiza peticiones a una URL influida por el cliente.",
    "API8:2023": "Posible configuración de seguridad incorrecta de la API (CORS, depuración, errores, cabeceras).",
    "API9:2023": "Posible gestión inadecuada del inventario de la API (versiones antiguas, entornos o documentación expuestos).",
    "API10:2023": "Posible consumo inseguro de otra API: se confía en sus respuestas o en el canal sin validarlos.",
}

# Patrones combinados del análisis estático, redactados para el reporte.
DESCRIPCION_PATRON = {
    "x_id_ruta_sin_propiedad": "el endpoint obtiene un objeto por el identificador de la ruta sin verificar que pertenezca al usuario",
    "x_usuario_sin_propiedad": "se busca un objeto por id sin compararlo con el usuario autenticado",
    "x_ruta_sin_autenticacion": "el endpoint no muestra un mecanismo de autenticación",
    "x_ruta_privilegiada_sin_rol": "una operación de modificación o administración no comprueba el rol",
    "x_ruta_admin_sin_control": "una ruta administrativa no tiene autenticación ni control de rol",
    "x_asignacion_sin_filtro": "se copian al objeto todas las propiedades recibidas",
    "x_objeto_sensible_sin_filtro": "se devuelve un objeto con datos sensibles sin seleccionar propiedades",
    "x_coleccion_sin_paginacion": "se devuelve una colección completa sin paginación",
    "x_login_sin_limite": "el endpoint de autenticación no limita los intentos",
    "x_subida_sin_limite": "se aceptan archivos sin límite de tamaño",
    "x_entrada_sql": "datos de la petición llegan a una consulta SQL construida dinámicamente",
    "x_entrada_comando": "datos de la petición llegan a la ejecución de un comando",
    "x_entrada_eval": "datos de la petición llegan a una evaluación dinámica de código",
    "x_entrada_archivo_sin_normalizar": "datos de la petición forman una ruta de archivo sin normalizarla",
    "x_entrada_peticion_sin_lista": "datos de la petición determinan el destino de una petición saliente",
    "x_entrada_html_sin_escape": "datos de la petición se escriben en HTML sin codificar",
    "x_entrada_deserializacion": "datos de la petición se deserializan",
    "x_entrada_redireccion": "datos de la petición determinan una redirección",
    "x_entrada_xml": "datos de la petición se procesan con un analizador XML sin protección",
    "x_entrada_nosql": "datos de la petición se usan directamente en una consulta NoSQL",
    "x_jwt_inseguro": "el token se acepta sin verificar su firma o expiración",
    "x_secreto_sin_gestor": "hay un secreto escrito literalmente",
    "x_error_expuesto": "el detalle del error se devuelve al cliente",
    "x_peticion_sin_timeout": "la petición a otro servicio no define tiempo de espera",
    "x_respuesta_externa_sin_validar": "la respuesta de otra API se usa sin validarla",
    "x_recurso_propio_sin_propiedad": "se accede a un recurso del usuario por su id sin verificar el propietario",
    "x_aleatorio_sensible": "se usa un generador aleatorio no criptográfico para un valor sensible",
}

# Categorías que requieren validación dinámica o revisión manual por naturaleza (PDF, sección 8.3.2).
REQUIEREN_REVISION_MANUAL = {"A01:2025", "A06:2025", "A09:2025", "API1:2023", "API5:2023", "API6:2023", "API9:2023"}

# ---------------------------------------------------------------------------------------------
# Base de conocimiento por CWE: (problema, recomendación, severidad base)
# Severidades: Crítica, Alta, Media, Baja.
# ---------------------------------------------------------------------------------------------
CONOCIMIENTO = {
    22: ("Ruta de archivo construida con datos del usuario (path traversal).",
         "Normalizar la ruta (realpath/getCanonicalPath) y verificar que quede dentro del directorio permitido; usar listas blancas de nombres.", "Alta"),
    78: ("Comando del sistema operativo construido con datos variables (inyección de comandos).",
         "Evitar el shell: ejecutar el programa con una lista de argumentos (subprocess sin shell=True, ProcessBuilder, execFile) y validar la entrada con listas blancas.", "Crítica"),
    79: ("Datos del usuario se insertan en HTML sin codificar (Cross-Site Scripting).",
         "Codificar la salida según el contexto (plantillas con escape automático, textContent) y sanitizar el HTML permitido con una librería probada.", "Media"),
    89: ("Consulta SQL construida por concatenación o interpolación de datos (inyección SQL).",
         "Usar consultas parametrizadas o el ORM con parámetros enlazados; nunca concatenar datos en el texto SQL.", "Crítica"),
    90: ("Filtro LDAP construido con datos del usuario (inyección LDAP).",
         "Escapar los valores con la función de codificación LDAP del framework y validar la entrada.", "Alta"),
    94: ("Código evaluado dinámicamente a partir de datos variables (inyección de código).",
         "Eliminar eval/exec/Function sobre datos externos; usar analizadores específicos (JSON.parse, int()) y listas blancas.", "Crítica"),
    95: ("Evaluación dinámica (eval) de datos variables.",
         "Reemplazar eval por conversiones de tipo o analizadores seguros; nunca evaluar datos de la petición.", "Crítica"),
    113: ("Cabecera HTTP construida con datos del usuario (CRLF / response splitting).",
          "Validar y eliminar caracteres de control (\\r, \\n) de los valores antes de escribir cabeceras.", "Media"),
    117: ("Datos del usuario escritos en los logs sin neutralizar (log forging).",
          "Neutralizar saltos de línea y caracteres de control antes de registrar, o usar logging estructurado.", "Baja"),
    200: ("Exposición de información sensible en la respuesta.",
          "Devolver solo los campos necesarios mediante DTO/serializadores explícitos y ocultar datos internos.", "Media"),
    209: ("Detalles internos de errores o trazas devueltos al cliente.",
          "Devolver mensajes genéricos al cliente y registrar el detalle solo en los logs del servidor.", "Media"),
    215: ("Información de depuración expuesta.", "Desactivar la depuración en producción y controlar su activación por entorno.", "Media"),
    250: ("El servicio o contenedor se ejecuta con privilegios innecesarios (root).",
          "Crear y usar un usuario sin privilegios (USER en el Dockerfile), sin modo privilegiado ni capacidades extra.", "Media"),
    256: ("Contraseña almacenada o comparada en texto plano.", "Almacenar solo hashes con bcrypt, scrypt o argon2 y comparar con la función del algoritmo.", "Alta"),
    259: ("Contraseña escrita en el código.", "Leer las credenciales de variables de entorno o de un gestor de secretos y rotarlas.", "Alta"),
    269: ("Gestión incorrecta de privilegios entre usuarios y funciones administrativas.",
          "Comprobar el rol en el servidor antes de ejecutar funciones privilegiadas y aplicar mínimo privilegio.", "Alta"),
    276: ("Permisos por defecto demasiado amplios.", "Asignar permisos mínimos a archivos, directorios y recursos.", "Media"),
    284: ("Control de acceso incorrecto.", "Aplicar autorización centralizada en el servidor con denegación por defecto.", "Alta"),
    285: ("Autorización incorrecta: no se verifica que el usuario pueda acceder al recurso o a la función.",
          "Verificar en el servidor la propiedad del objeto y el rol del usuario antes de procesar la petición.", "Alta"),
    287: ("Autenticación incorrecta.", "Usar un mecanismo de autenticación probado y validar la identidad en cada petición.", "Alta"),
    295: ("Validación de certificados TLS deshabilitada.", "Mantener la verificación de certificados activa (verify=True, rejectUnauthorized) y usar un almacén de confianza.", "Alta"),
    306: ("Endpoint o función crítica accesible sin autenticación.", "Exigir autenticación (guard, filtro o dependencia de seguridad) en todos los endpoints no públicos.", "Alta"),
    307: ("Intentos de autenticación sin límite (fuerza bruta).", "Limitar intentos por usuario e IP, añadir retardos progresivos, bloqueo temporal o CAPTCHA.", "Media"),
    311: ("Datos sensibles sin cifrar.", "Cifrar los datos sensibles en tránsito y en reposo.", "Media"),
    312: ("Información sensible almacenada en texto claro.", "Cifrar o eliminar los datos sensibles almacenados.", "Media"),
    319: ("Transmisión de información sensible sin cifrar (HTTP).", "Usar HTTPS/TLS en todas las comunicaciones, incluidas las internas entre microservicios.", "Media"),
    321: ("Clave criptográfica o secreto de firma fijo en el código.", "Cargar las claves desde un gestor de secretos o variables de entorno y rotarlas.", "Alta"),
    326: ("Fuerza criptográfica insuficiente (clave corta o protocolo obsoleto).", "Usar claves de longitud recomendada y TLS 1.2 o superior.", "Media"),
    327: ("Algoritmo criptográfico roto o modo inseguro (DES, RC4, ECB).", "Usar AES-GCM o ChaCha20-Poly1305 con claves gestionadas.", "Media"),
    328: ("Hash débil (MD5/SHA-1).", "Usar SHA-256 o superior; para contraseñas, bcrypt/scrypt/argon2.", "Media"),
    330: ("Valores aleatorios predecibles.", "Usar un generador criptográfico (secrets, SecureRandom, crypto.randomBytes).", "Media"),
    338: ("Generador aleatorio no criptográfico usado para valores de seguridad.", "Usar secrets / SecureRandom / crypto.randomBytes para tokens, contraseñas e identificadores.", "Media"),
    345: ("Verificación insuficiente de la autenticidad de los datos.", "Verificar firmas o MAC de los datos recibidos.", "Media"),
    346: ("Validación de origen incorrecta (CORS permisivo con credenciales).", "Definir una lista blanca de orígenes; no reflejar el origen ni combinar '*' con credenciales.", "Media"),
    347: ("Firma del token (JWT) no verificada o algoritmo 'none' aceptado.", "Verificar siempre la firma con algoritmos explícitos y validar expiración, emisor y audiencia.", "Alta"),
    352: ("Protección CSRF desactivada en una aplicación con sesiones.", "Mantener la protección CSRF o usar tokens en cabecera (no cookies) para autenticar la API.", "Media"),
    359: ("Datos personales expuestos en las propiedades del objeto devuelto.", "Devolver solo los campos necesarios mediante DTO o serializadores explícitos.", "Media"),
    377: ("Archivo temporal creado de forma insegura.", "Usar funciones seguras (mkstemp, Files.createTempFile) con permisos restringidos.", "Baja"),
    384: ("Fijación de sesión.", "Regenerar el identificador de sesión después del inicio de sesión.", "Media"),
    390: ("Excepción capturada y silenciada.", "Registrar y manejar la excepción de forma específica; no ocultar fallos de seguridad.", "Baja"),
    400: ("Consumo de recursos no controlado.", "Aplicar límites de tamaño, tiempo y cantidad a las operaciones costosas.", "Media"),
    434: ("Subida de archivos sin restringir tipo ni tamaño.", "Validar extensión y tipo MIME con lista blanca, limitar tamaño y guardar fuera de la raíz web con nombre generado.", "Alta"),
    489: ("Modo de depuración activo.", "Desactivar el modo debug en producción y controlarlo por variables de entorno.", "Media"),
    494: ("Código o recursos descargados sin verificar su integridad.", "Verificar sumas de comprobación o firmas y evitar descargas remotas en tiempo de construcción.", "Media"),
    501: ("Datos no confiables almacenados en la sesión (frontera de confianza).", "Validar los datos antes de guardarlos en la sesión.", "Media"),
    502: ("Deserialización de datos no confiables.", "Usar formatos de solo datos (JSON) con validación de esquema; evitar pickle/ObjectInputStream/yaml.load sobre datos externos.", "Crítica"),
    521: ("Requisitos de contraseña débiles.", "Exigir longitud mínima y comprobar contraseñas comprometidas.", "Media"),
    522: ("Credenciales insuficientemente protegidas.", "Transmitir y almacenar credenciales cifradas y nunca en la URL ni en logs.", "Alta"),
    532: ("Datos sensibles escritos en los logs.", "No registrar contraseñas, tokens ni datos personales; enmascararlos.", "Media"),
    548: ("Listado de directorios expuesto.", "Desactivar el listado de directorios en el servidor.", "Baja"),
    601: ("Redirección a una URL controlada por el usuario (open redirect).", "Redirigir solo a rutas internas o a una lista blanca de dominios.", "Media"),
    611: ("Procesamiento de entidades externas XML (XXE).", "Deshabilitar DTD y entidades externas en el analizador XML.", "Alta"),
    613: ("Expiración de sesión o token insuficiente.", "Definir y validar la expiración de tokens y sesiones; invalidarlos al cerrar sesión.", "Media"),
    614: ("Cookie sensible sin el atributo Secure.", "Marcar las cookies de sesión con Secure, HttpOnly y SameSite.", "Baja"),
    636: ("Fallo abierto: ante un error se concede el acceso.", "Fallar de forma cerrada: ante cualquier excepción denegar la operación.", "Alta"),
    639: ("Acceso a un objeto por un identificador controlado por el usuario sin comprobar su propiedad (IDOR/BOLA).",
          "Filtrar la consulta por el usuario autenticado (p. ej. findByIdAndOwner) o comprobar la propiedad antes de devolver o modificar el objeto.", "Alta"),
    643: ("Consulta XPath construida con datos del usuario.", "Usar consultas XPath parametrizadas o escapar los valores.", "Alta"),
    693: ("Mecanismo de protección ausente (cabeceras de seguridad).", "Configurar cabeceras de seguridad (helmet, Spring Security headers).", "Baja"),
    703: ("Condición excepcional no manejada correctamente.", "Manejar los errores de forma explícita y segura.", "Baja"),
    732: ("Permisos incorrectos sobre un recurso crítico.", "Restringir los permisos al mínimo necesario.", "Media"),
    754: ("Comprobación incorrecta de condiciones excepcionales.", "Validar los valores de retorno y estados de error.", "Baja"),
    755: ("Manejo incorrecto de excepciones.", "Capturar excepciones específicas y responder de forma controlada.", "Baja"),
    770: ("Recursos asignados sin límites ni control de frecuencia (sin rate limiting/paginación).",
          "Aplicar limitación de frecuencia (rate limiting), paginación con tamaño máximo y límites de tamaño de carga.", "Media"),
    778: ("Eventos de seguridad sin registrar.", "Registrar los eventos de autenticación y autorización y configurar alertas.", "Baja"),
    798: ("Credenciales o secretos escritos en el código o en la configuración.",
          "Mover los secretos a variables de entorno o a un gestor de secretos, y rotar los que ya fueron expuestos.", "Alta"),
    799: ("Control insuficiente de la frecuencia de interacción.", "Limitar la frecuencia de peticiones por usuario e IP.", "Media"),
    829: ("Inclusión de funcionalidad desde una fuente no confiable.", "Usar solo fuentes confiables y verificar su integridad.", "Media"),
    862: ("Falta de verificación de autorización en el endpoint.", "Añadir control de acceso por rol (guards, @PreAuthorize, dependencias de seguridad) con denegación por defecto.", "Alta"),
    863: ("Autorización incorrecta.", "Revisar la lógica de autorización y comprobar rol y propiedad en el servidor.", "Alta"),
    915: ("Asignación masiva: se copian al objeto todas las propiedades enviadas por el cliente.",
          "Usar DTO con lista blanca de campos editables y no asignar el cuerpo de la petición directamente a la entidad.", "Alta"),
    916: ("Contraseña protegida con un hash rápido o sin sal.", "Usar bcrypt, scrypt, argon2 o PBKDF2 con sal y factor de coste.", "Alta"),
    918: ("Petición del servidor hacia una URL controlada por el usuario (SSRF).",
          "Validar el destino con una lista blanca de dominios, bloquear direcciones internas y no seguir redirecciones arbitrarias.", "Alta"),
    942: ("Política CORS permisiva (origen '*').", "Restringir los orígenes permitidos a una lista explícita.", "Media"),
    943: ("Consulta NoSQL construida con datos del usuario (inyección NoSQL).", "Validar el tipo de los datos y usar operadores parametrizados; rechazar objetos con operadores ($ne, $gt).", "Alta"),
    1004: ("Cookie sensible sin el atributo HttpOnly.", "Marcar las cookies de sesión con HttpOnly, Secure y SameSite.", "Baja"),
    1059: ("API sin inventario o documentación controlada (versiones antiguas o documentación expuesta).",
           "Retirar versiones antiguas, inventariar los endpoints y deshabilitar Swagger/OpenAPI públicos en producción.", "Baja"),
    1104: ("Uso de componentes sin mantenimiento o con versión no fijada.", "Fijar versiones, actualizar componentes y revisar sus vulnerabilidades conocidas.", "Media"),
    1188: ("Valores por defecto inseguros.", "Configurar valores seguros explícitos en cada entorno.", "Media"),
    1321: ("Contaminación de prototipo (prototype pollution).", "Bloquear las claves __proto__, constructor y prototype y usar objetos sin prototipo.", "Alta"),
    1333: ("Expresión regular con complejidad exponencial (ReDoS).", "Evitar expresiones regulares construidas con datos del usuario y limitar la longitud de la entrada.", "Media"),
    1336: ("Plantilla del servidor construida con datos del usuario (SSTI).", "No construir plantillas con datos del usuario; pasarlos como variables de contexto.", "Crítica"),
    1357: ("Dependencia de un componente no confiable o sin verificar.", "Usar imágenes y paquetes de fuentes oficiales con versión fijada y verificación de integridad.", "Media"),
}


@lru_cache(maxsize=1)
def mapeo():
    return json.loads((DATOS / "mapeo_cwe.json").read_text(encoding="utf-8"))


def numero_cwe(cwe):
    texto = str(cwe).upper().replace("CWE-", "").strip()
    return int(texto) if texto.isdigit() else None


def cwe_a_owasp2025(cwe):
    """Categoría OWASP Top 10:2025 del CWE (oficial o extendida), o None."""
    n = numero_cwe(cwe)
    if n is None:
        return None
    m = mapeo()
    if str(n) in m["owasp2025_oficial"]:
        return m["owasp2025_oficial"][str(n)]
    ext = m["owasp2025_extendida"].get(str(n))
    return ext["categoria"] if ext else None


def cwe_a_api2023(cwe, consume_api=False):
    """Categorías OWASP API Security Top 10:2023 del CWE.

    Las relaciones de contexto (CWE-20, 200, 295, 319 -> API10) solo se aplican cuando el
    fragmento consume una API externa.
    """
    n = numero_cwe(cwe)
    if n is None:
        return []
    m = mapeo()
    cats = list(m["api2023_oficial"].get(str(n), []))
    ext = m["api2023_extendida"].get(str(n))
    if ext:
        cats += [c for c in ext["categorias"] if c not in cats]
    if n in (20, 200) and not consume_api:
        # Referencias oficiales de API10 demasiado genéricas fuera del contexto de consumo de API.
        cats = [c for c in cats if c != "API10:2023"]
    ctx = m["api2023_contexto_consumo"].get(str(n))
    if consume_api and ctx and ctx not in cats:
        cats.append(ctx)
    return cats


def nombre_cwe(cwe):
    n = numero_cwe(cwe)
    return mapeo()["nombres_cwe"].get(str(n), "") if n is not None else ""


def nombre_categoria(codigo, idioma="es"):
    par = CATEGORIAS.get(codigo)
    if not par:
        return codigo
    return par[0] if idioma == "es" else par[1]


def conocimiento(cwe):
    """(problema, recomendación, severidad_base) del CWE, o None."""
    n = numero_cwe(cwe)
    return CONOCIMIENTO.get(n) if n is not None else None

"""Extracción de características de seguridad (análisis estático ligero).

Cada *indicador* reconoce un patrón sintáctico relacionado con la seguridad (una fuente de
entrada, una consulta dinámica, un guard de autorización, una opción de configuración...).
Los indicadores NO asignan categorías OWASP: producen variables numéricas que el modelo de
minería de datos combina con la representación TF-IDF del código, y sirven como evidencia
(línea y texto) para explicar cada hallazgo.

Familias (sección 7.3 del enunciado):
 entrada, bd (consultas dinámicas), auth (autenticación/autorización), validacion, cripto,
 errores, config (permisos y seguridad), credenciales (tokens/secretos), rutas (endpoints
 REST), externo (dependencias y APIs externas), recursos, inyeccion, datos, metricas.
"""

import re
from dataclasses import dataclass

import numpy as np

F = re.IGNORECASE | re.MULTILINE


@dataclass(frozen=True)
class Indicador:
    nombre: str
    familia: str
    patron: str
    descripcion: str
    sensible: bool = False   # True = distingue mayúsculas

    def compilar(self):
        return re.compile(self.patron, re.MULTILINE if self.sensible else F)


SQL = (r"(?:\bselect\b[^\"'`\n]{0,80}\bfrom\b|\binsert\s+into\b|\bupdate\s+\w+\s+set\b|\bdelete\s+from\b|"
       r"\bwhere\s+\w+\s*(?:=|<|>|\blike\b|\bin\b)|\border\s+by\b|\bunion\s+select\b|\{call\b)")
STR_SQL = (r"(?:\"[^\"\n]*" + SQL + r"[^\"\n]*\"|'[^'\n]*" + SQL + r"[^'\n]*'|`[^`]*" + SQL + r"[^`]*`)")
_PH = r"(?:\?|%s|:\w+|\$\d)"
STR_SQL_PARAM = (r"(?:\"[^\"\n]*" + SQL + r"[^\"\n]*" + _PH + r"[^\"\n]*\"|'[^'\n]*" + SQL + r"[^'\n]*" + _PH + r"[^'\n]*')")
ID_RUTA = r"(?:/:\w*id\w*|\{\s*\w*id\w*\s*\}|<(?:int:|string:|uuid:)?\w*id\w*>|/:\w+\b|\{\w+\})"
USUARIO_ACTUAL = (r"(?:req\.user|request\.user|current_user|currentUser|get_current_user|g\.user|principal|"
                  r"@AuthenticationPrincipal|getAuthentication\(\)|SecurityContextHolder|authentication\.getName|"
                  r"@CurrentUser|@User\(\)|user_id_from_token|token\.sub|jwt\.sub|payload\.sub|get_jwt_identity|"
                  r"auth\.uid|req\.auth|res\.locals\.user|userFromToken|getCurrentUser|identity\.id)")

INDICADORES = [
    # --- Entrada no confiable ------------------------------------------------------------------
    Indicador("entrada_http", "entrada",
              r"\breq\.(body|query|params|headers|cookies|files?|get\()|\brequest\.(args|form|json|get_json|values|data|files|cookies|headers|"
              r"GET|POST|query_params|path_params|body|query|params|view_args|stream)|@(RequestParam|PathVariable|RequestBody|"
              r"RequestHeader|CookieValue|ModelAttribute)\b|\bget(Parameter|ParameterValues|ParameterMap|Header|Headers|QueryString|"
              r"Cookies|InputStream|Reader|PathInfo|RequestURI)\s*\(|@(Body|Param|Query|Headers|Req)\s*\(|\b(Query|Path|Body|Form|"
              r"Header|Cookie|File)\s*\(\s*(\.\.\.|None|default|[\w\"'])|\bctx\.(request|params|query)|\bevent\.(body|queryStringParameters)",
              "Lee datos enviados por el cliente en la petición"),
    Indicador("entrada_otros", "entrada",
              r"\binput\s*\(|\bsys\.argv|\bprocess\.argv|\bSystem\.in\b|\bScanner\s*\(|\breadline\(|\bos\.environ\[|\bprocess\.env\.\w+\s*\|\|",
              "Lee datos externos (consola, argumentos, entorno)"),
    # --- Endpoints REST -----------------------------------------------------------------------
    Indicador("ruta_definida", "rutas",
              r"@(Get|Post|Put|Patch|Delete|Request|All)(Mapping)?\s*\(|@(Get|Post|Put|Patch|Delete)\b|@(app|router|api|bp|blueprint|\w+_router)\."
              r"(get|post|put|patch|delete|route|api_route)\s*\(|\b(app|router|api|route|server)\.(get|post|put|patch|delete|all|route)\s*\(\s*['\"`]|"
              r"@(api_view|action)\s*\(|\bpath\s*\(\s*['\"]|@Path\s*\(|methods\s*=\s*\[|"
              r"\bdef\s+(get|post|put|patch|delete|list|retrieve|update|destroy|create)\s*\(\s*self\s*,\s*request\b",
              "Define un endpoint HTTP"),
    Indicador("parametro_ruta_id", "rutas",
              r"['\"`][^'\"`\n]*" + ID_RUTA + r"[^'\"`\n]*['\"`]|['\"`]:\w+['\"`]|@PathVariable\b|@Param\s*\(\s*['\"]\w*[iI]d['\"]|"
              r"\bdef\s+\w+\s*\([^)]*\b\w+_id\b|\breq\.params\.\w*[iI]d\b|\brequest\.(args|GET)\.get\(\s*['\"]\w*_?id['\"]",
              "El endpoint recibe un identificador de objeto en la ruta"),
    Indicador("metodo_modificacion", "rutas",
              r"@(Put|Patch|Delete)(Mapping)?\b|\.(put|patch|delete)\s*\(\s*['\"`]|methods\s*=\s*\[[^\]]*(PUT|PATCH|DELETE)|"
              r"RequestMethod\.(PUT|PATCH|DELETE)",
              "Endpoint que modifica o elimina datos"),
    Indicador("ruta_administrativa", "rutas",
              r"['\"`][^'\"`\n]*/(admin|internal|management|manage|backoffice|superuser|staff|roles?|permissions?|all-users|users/all|"
              r"debug|actuator|config|settings|system)\b[^'\"`\n]*['\"`]|def\s+\w*(admin|delete_user|promote|set_role)\w*|"
              r"\b(deleteUser|delete_user|promoteUser|setRole|set_role|makeAdmin|grantRole|updateRole|change_role|disableUser|ban\w*)\s*\(",
              "Ruta o función administrativa / privilegiada"),
    Indicador("recurso_de_usuario", "rutas",
              r"\b(orders?|invoices?|payments?|accounts?|cards?|documents?|messages?|address(es)?|bookings?|tickets?|reports?|"
              r"receipts?|contracts?|wallets?|transactions?|appointments?|shipments?|notes?|carts?|profiles?|statements?|"
              r"subscriptions?|files?|uploads?|records?|vehicles?)\b",
              "Opera sobre un recurso que normalmente pertenece a un usuario"),
    Indicador("ruta_version", "rutas", r"['\"`]/?(api/)?v\d+/|/api/v\d+\b|basePath\s*:\s*/?v\d", "Ruta con versión explícita de la API"),
    Indicador("ruta_autenticacion", "rutas",
              r"['\"`][^'\"`\n]*/(login|signin|sign-in|auth|token|authenticate|otp|reset|forgot|forget|verify|password|register|signup)\b"
              r"[^'\"`\n]*['\"`]|def\s+\w*(login|signin|authenticate|reset_password|verify_otp|check_otp)\w*",
              "Endpoint de autenticación (login, OTP, recuperación de contraseña)"),
    # --- Acceso a datos ------------------------------------------------------------------------
    Indicador("sql_dinamico", "bd",
              STR_SQL + r"\s*(?:\+|\.\s*(?=[$\w(])|\|\||%\s*[\w(])|"
              r"\bf[\"'][^\"'\n]*" + SQL + r"[^\"'\n]*\{|`[^`]*" + SQL + r"[^`]*\$\{|"
              r"(?:String\.format|sprintf|format)\s*\(\s*[\"'][^\"'\n]*" + SQL + r"|[\"'][^\"'\n]*" + SQL + r"[^\"'\n]*\{\w*\}[\"']\s*\.format\(|"
              r"[\w)\]]\s*\+\s*[\"']\s*(?:where|and|or|from|order\s+by|values\s*\(|limit)\b",
              "Consulta SQL construida con concatenación o interpolación"),
    Indicador("sql_parametrizado", "bd",
              r"prepareStatement\s*\(|\.set(String|Int|Long|Object)\s*\(\s*\d|createQuery\s*\([^+]*:\w+|" + STR_SQL_PARAM + r"\s*,|\.(query|execute|raw)\s*\([^,()]+,\s*[\[(\{]|bindparam|@Query\s*\([^+]*[:?]\w*",
              "Consulta con parámetros enlazados"),
    Indicador("orm_crudo", "bd",
              r"\.(raw|extra|rawQuery|query_raw|createNativeQuery|executeQuery|executeUpdate|nativeQuery)\s*\(|\bsequelize\.query\s*\(|"
              r"\btext\s*\(\s*f[\"']|\$where\b|\$expr\b|\bmapReduce\b|\.execute\s*\(\s*(f[\"']|[\"'][^\"']*[\"']\s*[+%])",
              "Consulta nativa o cruda a la base de datos"),
    Indicador("busqueda_por_id", "bd",
              r"\b(findById|findByPk|findOne|findUnique|findFirst|getById|getOne|getReferenceById|get_object_or_404|findByIdAndUpdate|"
              r"findByIdAndDelete|findOneAndUpdate|deleteById|findByUsername|findByEmail)\s*\(|\.query\.get\s*\(|\bsession\.get\s*\(|"
              r"\.objects\.get\s*\(|\.filter(_by)?\s*\(\s*(\w+\.)?id\s*==?|\bem\.find\s*\(|\.get\s*\(\s*\w*[iI]d\b|\bWHERE\s+\w*id\s*=",
              "Obtiene o modifica un objeto a partir de su identificador"),
    Indicador("consulta_coleccion", "bd",
              r"\b(findAll|find_all|getAll|listAll|all_users|find)\s*\(\s*(\)|\{\s*\})|\.objects\.all\(\)|\.query\.all\(\)|\.all\(\)\s*$|"
              r"SELECT\s+\*\s+FROM\s+\w+\s*[\"';]",
              "Recupera una colección completa de registros"),
    Indicador("paginacion", "recursos",
              r"\b(limit|take|skip|offset|page_size|pageSize|per_page|perPage|Pageable|PageRequest|paginate|paginator|maxResults|"
              r"setMaxResults|LIMIT\s+\d|\.slice\(\s*0\s*,)\b",
              "Aplica paginación o límite al número de resultados"),
    Indicador("nosql_dinamico", "bd",
              r"\.(find|findOne|update|updateOne|deleteOne|aggregate|where)\s*\(\s*(req\.(body|query|params)|request\.(json|args|get_json))|"
              r"\$where\s*:|['\"]\$(ne|gt|regex|where)['\"]|\{\s*\$where",
              "Consulta NoSQL construida a partir de la petición"),
    # --- Autenticación y autorización ----------------------------------------------------------
    Indicador("guard_autenticacion", "auth",
              r"@UseGuards\b|AuthGuard|JwtAuthGuard|@PreAuthorize|@PostAuthorize|@Secured|@RolesAllowed|@login_required|@jwt_required|"
              r"@token_required|@auth_required|@requires_auth|@authenticated|@permission_classes|IsAuthenticated|Depends\s*\(\s*(get_current|"
              r"current_user|auth|verify|oauth2|security|require)|Security\s*\(\s*get_current|passport\.authenticate|\b(requireAuth|isAuthenticated|"
              r"ensureAuthenticated|authenticateToken|verifyToken|validateToken|checkAuth|authMiddleware|auth\.required|authenticate|authorize|"
              r"jwtCheck|protect|requireLogin|withAuth)\b|\.authenticated\(\)|@Authenticated|@Auth\(|login_manager",
              "Exige autenticación en el endpoint"),
    Indicador("acceso_publico", "auth",
              r"permitAll\(\)|@PermitAll|AllowAny|@Public\(\)|@SkipAuth|anonymous\(\)|auth\.optional|security\s*:\s*\[\s*\]|@csrf_exempt",
              "Endpoint declarado como público / sin autenticación"),
    Indicador("verificacion_rol", "auth",
              r"\bhasRole\b|hasAnyRole|hasAuthority|@Roles\s*\(|RolesGuard|@RolesAllowed|\b(is_admin|isAdmin|is_superuser|is_staff|isSuperUser)\b|"
              r"\brole\s*(==|===|!=|!==|in\b|\.equals)|\broles?\.(includes|contains|indexOf)\s*\(|ROLE_ADMIN|admin_required|@admin_only|"
              r"\b(check|require|verify|ensure)(_)?(role|admin|permission)s?\b|getAuthorities|UserRole\.|Role\.ADMIN",
              "Comprueba el rol o los permisos del usuario"),
    Indicador("usuario_actual", "auth", USUARIO_ACTUAL, "Usa la identidad del usuario autenticado"),
    Indicador("verificacion_propiedad", "auth",
              r"\b(owner|owner_id|ownerId|user_id|userId|author|author_id|authorId|created_by|createdBy|account_id|accountId|customer_id|"
              r"customerId|profile_id)\b\s*(==|===|!=|!==|\.equals|\bis\b)|(==|===|!=|!==|\.equals\()\s*" + USUARIO_ACTUAL +
              r"|" + USUARIO_ACTUAL + r"[\w.()]*\s*(==|===|!=|!==|\.equals\()|\b(find|get|filter|query)\w*(ByIdAnd|And)(User|Owner|Account|Customer)\w*\s*\(|"
              r"\b(where|filter|filter_by|findOne|findFirst|find)\s*\([^)\n]*(owner|user_?id|userId|author|account_?id)\s*[:=]",
              "Compara el objeto con el usuario autenticado (verificación de propiedad)"),
    Indicador("validacion_entrada", "validacion",
              r"@Valid\b|@Validated|@(NotNull|NotBlank|NotEmpty|Size|Min|Max|Pattern|Email|Positive)\b|@Is(String|Int|Email|UUID|NotEmpty|"
              r"Number|Enum|Optional|Boolean)\b|ValidationPipe|ParseIntPipe|ParseUUIDPipe|class-validator|\bJoi\.|\byup\.|\bz\.(object|string|number)|"
              r"express-validator|\b(check|body|param|query)\s*\(\s*['\"]\w+['\"]\s*\)\s*\.|validationResult|BaseModel\b|Field\s*\(|"
              r"constr\(|conint\(|\bvalidate\w*\s*\(|isinstance\s*\(|\bint\s*\(|\bparseInt\s*\(|\bNumber\s*\(|Integer\.parseInt|UUID\.fromString|"
              r"Long\.parseLong|\.matches\s*\(|re\.fullmatch|\bschema\.(validate|parse)|marshmallow|serializer\.is_valid",
              "Valida o convierte el tipo de la entrada"),
    # --- Credenciales y tokens -----------------------------------------------------------------
    Indicador("jwt", "credenciales", r"\bjwt\b|jsonwebtoken|\bJwts\b|\bjose\b|JWTVerifier|JwtDecoder|PyJWT|\bJWT_", "Usa tokens JWT"),
    Indicador("jwt_inseguro", "credenciales",
              r"verify_signature['\"]?\s*:\s*False|verify\s*=\s*False|algorithms?\s*[=:]\s*\[?\s*['\"]none['\"]|ignoreExpiration\s*:\s*true|"
              r"verify_exp['\"]?\s*:\s*False|\.decode\s*\(\s*\w+\s*\)|jwt\.decode\s*\([^)]*options|parseUnsecured|setSigningKey\s*\(\s*['\"]|"
              r"\.unsecured\(\)|alg\s*[:=]\s*['\"]none|algorithms\s*:\s*\[[^\]]*['\"]none['\"]|jwt\.decode\s*\(\s*\w+\s*,\s*options",
              "Token aceptado sin verificar firma o expiración"),
    Indicador("secreto_literal", "credenciales",
              r"\b\w*(password|passwd|pwd|secret|api_?key|apikey|token|private_?key|access_?key|client_?secret|auth_?key|signing_?key|"
              r"credential)s?\w*\b[\"']?\s*(=|:|=>)\s*[\"'](?![\s\"']|\$\{|\{\{|<|%\(|env|process\.env|os\.environ)[^\"'\n]{3,}[\"']|"
              r"\b(SECRET_KEY|JWT_SECRET|API_KEY|DB_PASSWORD|PASSWORD|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|"
              r"AWS_SECRET_ACCESS_KEY|SPRING_DATASOURCE_PASSWORD)\s*[:=]\s*(?![^\n]*\b(environ|getenv|process\.env|System\.getenv|ConfigService|settings\.|config\.get|secrets\.)\b)[\"']?(?!\$\{|\$\(|\{\{|<)[^\s\"'#$(\[]{3,}(?![(\[])|"
              r"^\s*[\w.-]*(password|secret|token|api[_-]?key)[\w.-]*\s*[=:]\s*(?![^\n]*\b(environ|getenv|process\.env|System\.getenv|ConfigService|settings\.|config\.get|secrets\.)\b)(?!\$\{|\{\{|\s*$)[^\s#$(\[]{3,}\s*$|"
              r"AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC )?PRIVATE KEY",
              "Secreto o credencial escrito literalmente"),
    Indicador("secreto_externo", "credenciales",
              r"os\.environ|os\.getenv|process\.env|System\.getenv|@Value\s*\(\s*\"\$\{|\$\{[A-Z_]+|settings\.\w*(SECRET|KEY|PASSWORD)|"
              r"config\.get\(|ConfigService|SecretsManager|KeyVault|vault",
              "Obtiene secretos de variables de entorno o de un gestor"),
    Indicador("hash_password_robusto", "cripto",
              r"\bbcrypt\b|\bargon2\b|\bscrypt\b|pbkdf2|BCryptPasswordEncoder|Argon2PasswordEncoder|passlib|password_hash\(|"
              r"make_password|check_password|generate_password_hash|check_password_hash|PasswordEncoder",
              "Usa un algoritmo robusto para contraseñas"),
    Indicador("password_plano", "credenciales",
              r"\bpassword\w*\s*(==|===|!=|!==)\s*\w|\w\s*(==|===|!=|!==)\s*\w*\.?password\b|\.equals\s*\(\s*\w*[pP]assword|"
              r"[pP]assword\w*\.equals\s*\(|password\s*=\s*request\.\w+.*\bsave\b",
              "Contraseña comparada o almacenada en texto plano"),
    Indicador("limite_intentos", "recursos",
              r"\b(attempts?|failed_?logins?|login_?attempts|lockout|lock_?account|max_?retries|retry_?count|captcha|recaptcha)\b|"
              r"too\s+many|429|TooManyRequests",
              "Controla el número de intentos"),
    # --- Criptografía ---------------------------------------------------------------------------
    Indicador("hash_debil", "cripto",
              r"\bmd5\b|\bsha1\b|SHA-?1['\"]|MessageDigest\.getInstance\s*\(\s*['\"](MD5|SHA-?1|MD2|MD4)|hashlib\.(md5|sha1)|"
              r"createHash\s*\(\s*['\"](md5|sha1)|DigestUtils\.(md5|sha1)|Hashing\.(md5|sha1)",
              "Algoritmo de hash débil (MD5/SHA-1)"),
    Indicador("cifrado_debil", "cripto",
              r"['\"](DES|DESede|3DES|RC2|RC4|Blowfish|ARCFOUR)(/|['\"])|/ECB/|\bECB\b|MODE_ECB|Cipher\.getInstance\s*\(\s*['\"]AES['\"]|"
              r"createCipher\s*\(|\bDES\.new|ARC4\.new|Blowfish\.new|NoPadding",
              "Algoritmo o modo de cifrado inseguro"),
    Indicador("aleatorio_debil", "cripto",
              r"Math\.random\s*\(|\brandom\.(random|randint|choice|choices|randrange|getrandbits|sample)\s*\(|new\s+(java\.util\.)?Random\s*\(|"
              r"\bRandom\(\)\.next|\brand\(\)|uuid1\s*\(|ThreadLocalRandom",
              "Generador aleatorio no criptográfico"),
    Indicador("aleatorio_seguro", "cripto",
              r"SecureRandom|\bsecrets\.|crypto\.randomBytes|crypto\.getRandomValues|randomUUID|os\.urandom|uuid4\s*\(|token_urlsafe",
              "Generador aleatorio criptográfico"),
    Indicador("tls_sin_verificar", "cripto",
              r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|InsecureSkipVerify|CERT_NONE|"
              r"_create_unverified_context|TrustAll|trustAllCerts|X509TrustManager|NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|"
              r"setHostnameVerifier|check_hostname\s*=\s*False|strict-ssl\s+false|--insecure|curl\s+-k\b|sslVerify\s*=\s*false",
              "Verificación de certificados TLS deshabilitada"),
    Indicador("http_texto_claro", "cripto",
              r"['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|example|schemas|www\.w3\.org|java\.sun|xml\.org|json-schema|"
              r"maven\.apache|www\.springframework|xmlns|purl\.org|ns\.adobe|www\.apache\.org)[^'\"\s]+|^\s*-?\s*url\s*:\s*http://(?!localhost)|"
              r"schemes\s*:\s*\[?\s*-?\s*['\"]?http\b|ftp://|telnet://|ws://",
              "Comunicación sin cifrar (HTTP/FTP/WS)"),
    # --- Inyección y operaciones peligrosas -------------------------------------------------------
    Indicador("ejecucion_comando", "inyeccion",
              r"\bos\.(system|popen|exec\w*|spawn\w*)\s*\(|\bsubprocess\.\w+\s*\(|\bcommands\.getoutput|Runtime\.getRuntime\(\)\.exec|"
              r"new\s+ProcessBuilder|\bchild_process\b|\b(exec|execSync|spawn|spawnSync|execFileSync)\s*\(|\bshelljs\b|\bpopen\s*\(",
              "Ejecuta comandos del sistema operativo"),
    Indicador("shell_activado", "inyeccion", r"shell\s*=\s*True|shell\s*:\s*true|['\"](/bin/)?(ba)?sh['\"]\s*,\s*['\"]-c['\"]|cmd(\.exe)?['\"]?\s*,\s*['\"]/c",
              "Comando ejecutado a través del intérprete de comandos"),
    Indicador("eval_dinamico", "inyeccion",
              r"(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(\s*(?![\"'])|new\s+Function\s*\(|setTimeout\s*\(\s*[\"'`]|setInterval\s*\(\s*[\"'`]|"
              r"vm\.(runIn\w*|Script)|ScriptEngine\w*\.eval|\.eval\s*\(|compile\s*\([^)]*['\"]exec['\"]|__import__\s*\(|"
              r"SpelExpressionParser|parseExpression\s*\(|Ognl\.|MVEL\.eval",
              "Evalúa código o expresiones dinámicas"),
    Indicador("deserializacion", "inyeccion",
              r"pickle\.loads?\s*\(|cPickle|\byaml\.load\s*\((?![^)]*SafeLoader)|yaml\.unsafe_load|ObjectInputStream|readObject\s*\(|"
              r"\bunserialize\s*\(|node-serialize|serialize\.unserialize|jsonpickle\.decode|marshal\.loads|XMLDecoder|enableDefaultTyping|"
              r"activateDefaultTyping|JsonTypeInfo\.Id\.CLASS|shelve\.open|dill\.loads|XStream\(\)",
              "Deserializa objetos con un formato que permite ejecutar código"),
    Indicador("html_sin_escape", "inyeccion",
              r"\.(innerHTML|outerHTML)\s*\+?=|document\.write\s*\(|dangerouslySetInnerHTML|insertAdjacentHTML|v-html|bypassSecurityTrust|"
              r"render_template_string\s*\(|\bMarkup\s*\(|mark_safe\s*\(|\|\s*safe\b|autoescape\s*(false|off)|res\.send\s*\([^)]*\+|"
              r"getWriter\(\)\.(print|println|write)\s*\([^)]*\+|\.html\s*\(\s*[\w$]+[^)]*\)|th:utext|<%=",
              "Escribe HTML con datos sin codificar"),
    Indicador("escape_salida", "validacion",
              r"\bescape\w*\s*\(|htmlspecialchars|DOMPurify|sanitize\w*\s*\(|encodeFor\w+|textContent|innerText|HtmlUtils\.htmlEscape|"
              r"StringEscapeUtils|bleach\.clean|markupsafe|xss\s*\(|Encode\.for|createTextNode",
              "Codifica o sanitiza la salida"),
    Indicador("acceso_archivo", "inyeccion",
              r"\bopen\s*\(|readFile\w*\s*\(|createReadStream|writeFile\w*\s*\(|sendFile\s*\(|res\.download\s*\(|new\s+File(Input|Output)?"
              r"(Stream|Reader|Writer)?\s*\(|Paths\.get\s*\(|Files\.(read|write|new|copy|delete)\w*\s*\(|send_file\s*\(|send_from_directory|"
              r"os\.(remove|unlink|rename)\s*\(|shutil\.|FileResponse\s*\(|unlink\w*\s*\(",
              "Accede a archivos del sistema"),
    Indicador("ruta_normalizada", "validacion",
              r"\bbasename\s*\(|realpath|normalize\s*\(|getCanonicalPath|getCanonicalFile|toRealPath|secure_filename|safe_join|"
              r"is_relative_to|commonpath|startsWith\s*\(\s*\w*(base|root|dir)|path\.resolve\([^)]*\)\s*\.startsWith",
              "Normaliza o restringe la ruta de archivo"),
    Indicador("redireccion", "inyeccion",
              r"\bredirect\s*\(|res\.redirect\s*\(|sendRedirect\s*\(|HttpResponseRedirect|RedirectView|['\"]redirect:|"
              r"RedirectResponse\s*\(|header\s*\(\s*['\"]Location",
              "Redirige a otra URL"),
    Indicador("xml_parser", "inyeccion",
              r"DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SAXReader|SAXBuilder|XMLReader|etree\.(parse|fromstring|XMLParser)|"
              r"\blxml\b|xml\.dom\.minidom|xml2js|libxmljs|DOMParser|parseXml|xml\.sax",
              "Procesa XML"),
    Indicador("xml_protegido", "validacion",
              r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|external-general-entities['\"]\s*,\s*false|resolve_entities\s*=\s*False|"
              r"defusedxml|setExpandEntityReferences\s*\(\s*false|IS_SUPPORTING_EXTERNAL_ENTITIES\s*,\s*false|noent\s*:\s*false",
              "Analizador XML con entidades externas deshabilitadas"),
    Indicador("ldap_xpath", "inyeccion",
              r"\.search\s*\([^)]*[\"'][^\"']*\(\w+=|DirContext|InitialDirContext|ldap\.|xpath\.(evaluate|compile)|XPathFactory|"
              r"\.xpath\s*\(|selectNodes\s*\(",
              "Consulta LDAP o XPath"),
    Indicador("plantilla_dinamica", "inyeccion",
              r"render_template_string\s*\(|Template\s*\(\s*[\w(]|Environment\s*\([^)]*\)\.from_string|ejs\.render\s*\(|pug\.(render|compile)\s*\(|"
              r"Handlebars\.compile\s*\(|Velocity\.evaluate|freemarker\.template|new\s+Template\s*\(|nunjucks\.renderString",
              "Construye plantillas dinámicamente"),
    Indicador("regex_dinamica", "recursos",
              r"new\s+RegExp\s*\(\s*(?![\"'/])|re\.(compile|match|search|findall)\s*\(\s*(?![rRbBuUfF]?[\"'])\w|Pattern\.compile\s*\(\s*(?![\"'])\w",
              "Expresión regular construida con datos variables"),
    Indicador("cabecera_respuesta", "inyeccion", r"\.(setHeader|addHeader|header|set)\s*\(\s*['\"][\w-]+['\"]\s*,\s*[^'\")]+\)|response\.headers\[",
              "Escribe cabeceras HTTP con valores variables"),
    # --- Peticiones salientes / consumo de APIs ----------------------------------------------------
    Indicador("peticion_saliente", "externo",
              r"\brequests\.(get|post|put|patch|delete|request|head)\s*\(|urllib\.request\.urlopen|urlopen\s*\(|\bhttpx\.|aiohttp\.|"
              r"\baxios(\.\w+)?\s*\(|\bfetch\s*\(|\bgot(\.\w+)?\s*\(|\bhttps?\.(get|request)\s*\(|\bneedle\.|\bsuperagent|RestTemplate|"
              r"restTemplate\.\w+|WebClient|HttpClient|OkHttpClient|HttpURLConnection|openConnection\s*\(|new\s+URL\s*\(|"
              r"\.openStream\s*\(|@FeignClient|HttpRequest\.newBuilder|request\s*\(\s*\{\s*(url|uri)",
              "Realiza peticiones HTTP a otro servicio"),
    Indicador("url_variable", "externo",
              r"\b\w*(url|uri|endpoint|host|target|callback|webhook|redirect|link|domain|server|image|avatar|feed|proxy)\w*\s*"
              r"(=|:)\s*(req\.|request\.|params|body|query|data\[|args|\w+\.get\()|(get|post|fetch|axios|urlopen|getForObject|"
              r"getForEntity|exchange|create|uri)\s*\(\s*(f[\"']|[\"'`][^\"'`]*[\"'`]\s*\+|`[^`]*\$\{|\w*(url|uri|link|target|host)\w*\s*[,)])",
              "La URL de destino se construye con un valor variable"),
    Indicador("lista_blanca", "validacion",
              r"allow_?list|white_?list|ALLOWED_\w+|allowed_(hosts|domains|urls|origins|schemes|extensions|types)|\.includes\s*\(\s*\w*(host|domain|origin)|"
              r"\bin\s+(ALLOWED|allowed|WHITELIST|PERMITTED)|startswith\s*\(\s*\(?['\"]https://|startsWith\s*\(\s*['\"]https://|"
              r"urlparse\s*\(|new\s+URL\s*\([^)]*\)\.(host|hostname)|getHost\s*\(\)",
              "Restringe valores mediante una lista blanca"),
    Indicador("timeout", "externo", r"\btimeout\s*[=:]|setConnectTimeout|setReadTimeout|connectTimeout|readTimeout|\.timeout\s*\(|Duration\.of",
              "Define un tiempo de espera"),
    Indicador("respuesta_externa_usada", "externo",
              r"\.json\(\)\s*[\[.]|response\.(data|body)\b|\.getBody\(\)|resp(onse)?\.json\(\)|\.text\(\)\s*\)|"
              r"json\.loads\s*\(\s*\w*(resp|response|r)\.(text|content)",
              "Usa directamente datos devueltos por otra API"),
    # --- Datos y propiedades --------------------------------------------------------------------
    Indicador("asignacion_masiva", "datos",
              r"Object\.assign\s*\(\s*\w+\s*,\s*(req\.body|body|dto|data|payload|input|changes|update\w*|attrs|params)\s*\)|"
              r"\{\s*\.\.\.\w+\s*,\s*\.\.\.(req\.body|body|dto|data|payload|input)\s*\}|\{\s*\.\.\.req\.body|new\s+\w+\s*\(\s*req\.body\s*\)|\.(create|update|updateOne|"
              r"findByIdAndUpdate|findOneAndUpdate|save|insert|build|set)\s*\(\s*([\w{},:\s]+,\s*)?req\.body\s*\)|\*\*\s*(request\.(json|"
              r"get_json\(\)|form|data)|data|payload|body|kwargs|update_data|item\.dict\(\)|\w+\.(dict|model_dump)\(\))|"
              r"setattr\s*\(\s*\w+\s*,\s*(key|k|attr|field)|BeanUtils\.copyProperties|\.update\(\s*request\.|modelMapper\.map\s*\(|"
              r"__dict__\.update|\.from_dict\s*\(|Object\.entries\(req\.body\)|for\s+\w+\s*(,\s*\w+)?\s+in\s+(data|request\.json|body)",
              "Copia todas las propiedades recibidas al objeto (asignación masiva)"),
    Indicador("campos_protegidos", "datos",
              r"\b(is_?admin|isAdmin|role|roles|is_?superuser|is_?staff|balance|credit|price|discount|verified|is_?verified|"
              r"account_?type|permissions|approved|status)\b",
              "Propiedades sensibles para la autorización (rol, saldo, estado)"),
    Indicador("datos_sensibles", "datos",
              r"\b(password|passwd|password_hash|hashed_password|ssn|social_security|credit_?card|card_?number|cvv|pin|salary|"
              r"dob|birth|api_?key|secret|token|otp|national_id|phone|address)\b",
              "Maneja datos personales o secretos"),
    Indicador("respuesta_objeto", "datos",
              r"res\.(json|send)\s*\(\s*\w+\s*\)|return\s+(jsonify\s*\(\s*\w+(\.__dict__|\.to_dict\(\)|\.serialize\(\))?\s*\)|"
              r"ResponseEntity\.ok\s*\(\s*\w+\s*\)|\w+\s*;)\s*$|return\s+\w+(\.__dict__|\.to_dict\(\)|\.to_json\(\)|\.json\(\))|"
              r"\.toJSON\(\)|model_to_dict|serializers\.serialize|json\.dumps\s*\(\s*\w+\.__dict__",
              "Devuelve el objeto completo en la respuesta"),
    Indicador("filtro_propiedades", "validacion",
              r"\b\w+(Dto|DTO|Response|Schema|Serializer|Out|Public|View)\b|response_model\s*=|@JsonIgnore|@Exclude|@Expose|"
              r"class\s+Meta\s*:|fields\s*=\s*[\[(]|exclude\s*=|\.select\s*\(\s*['\"]|\bpick\s*\(|\bomit\s*\(|only\s*\(|projection|"
              r"@JsonView|toResponse|to_public|serialize_user|attributes\s*:\s*\[|-password|excludeExtraneousValues|whitelist\s*:\s*true",
              "Selecciona explícitamente las propiedades expuestas o aceptadas"),
    # --- Recursos -------------------------------------------------------------------------------
    Indicador("limite_frecuencia", "recursos",
              r"rateLimit|rate_limit|RateLimiter|express-rate-limit|@Throttle|ThrottlerGuard|ThrottlerModule|slowapi|Limiter\s*\(|"
              r"@limiter\.limit|bucket4j|Bucket4j|resilience4j\.ratelimiter|RequestRateLimiter|limit_req|throttle",
              "Limita la frecuencia de peticiones"),
    Indicador("limite_tamano", "recursos",
              r"limit\s*:\s*['\"]\d+\s*[kmg]?b|MAX_CONTENT_LENGTH|max-file-size|max-request-size|maxFileSize|fileSize\s*:|"
              r"max_length\s*=|@Size\s*\(\s*max|maxLength|max_upload|client_max_body_size|maxItems|maximum\s*:|le\s*=\s*\d+|"
              r"Query\s*\([^)]*le\s*=|Math\.min\s*\(|min\s*\(\s*\w*(limit|size)|MAX_\w*(SIZE|LIMIT|PAGE)",
              "Define un tamaño o límite máximo"),
    Indicador("subida_archivo", "recursos",
              r"\bmulter\b|MultipartFile|request\.files|UploadFile|FileInterceptor|formidable|busboy|upload\.(single|array)|"
              r"multipart/form-data|\.save\s*\(\s*os\.path\.join|transferTo\s*\(",
              "Recibe archivos subidos por el cliente"),
    Indicador("bucle_con_entrada", "recursos",
              r"range\s*\(\s*int\s*\(\s*(request|req|data|args|params)|for\s*\([^;]*;[^;]*<\s*(req\.|request\.|parseInt\s*\(\s*req)|"
              r"new\s+Array\s*\(\s*(req\.|parseInt)|\.repeat\s*\(\s*(req\.|parseInt)|while\s*\([^)]*(req\.|request\.)",
              "Bucle o reserva cuyo tamaño depende de la petición"),
    # --- Errores y excepciones ------------------------------------------------------------------
    Indicador("manejo_excepciones", "errores", r"\btry\s*[:{]|\bcatch\s*\(|\bexcept\b|\.catch\s*\(|@ExceptionHandler|rescue\b",
              "Captura excepciones"),
    Indicador("excepcion_silenciada", "errores",
              r"catch\s*\([^)]*\)\s*\{\s*\}|except[^:\n]*:\s*(pass|\.\.\.|continue)\s*$|\.catch\s*\(\s*\(\s*\w*\s*\)\s*=>\s*\{\s*\}\s*\)|"
              r"catch\s*\([^)]*\)\s*\{\s*//[^\n]*\n\s*\}|catch\s*\{\s*\}",
              "Excepción capturada y silenciada"),
    Indicador("excepcion_generica", "errores",
              r"except\s*:|except\s+(Exception|BaseException)\b|catch\s*\(\s*(final\s+)?(Exception|Throwable|RuntimeException|Error)\s+\w+\s*\)|"
              r"catch\s*\(\s*\w+\s*\)\s*\{",
              "Captura excepciones de forma genérica"),
    Indicador("error_expuesto", "errores",
              r"printStackTrace\s*\(|traceback\.(format_exc|print_exc)|res\.(send|json|status\(\d+\)\.(send|json))\s*\([^)]*\b(err|error|e|ex)"
              r"(\.message|\.stack|\.toString\(\))?\s*[,})]|getMessage\(\)|getStackTrace|str\s*\(\s*(e|ex|err|error)\s*\)|"
              r"return\s+.*\b(e|ex|err|error)\.(message|args)|repr\s*\(\s*(e|ex)\s*\)|\.stack\b|include-stacktrace\s*[:=]\s*always|"
              r"include-message\s*[:=]\s*always|DEBUG_PROPAGATE_EXCEPTIONS|showStackTrace",
              "Devuelve detalles internos del error al cliente"),
    Indicador("fallo_abierto", "errores",
              r"(catch\s*\([^)]*\)|except[^:\n]*:)\s*\{?\s*\n?\s*(return\s+(true|True|next\(\))|next\s*\(\s*\)|\w*(allowed|authorized|valid|"
              r"isAuth\w*|granted)\s*=\s*(true|True))",
              "Ante una excepción se permite continuar (fallo abierto)"),
    Indicador("registro_eventos", "errores",
              r"\b(logger|log|LOGGER|LOG|logging|winston|pino|bunyan|console)\.(info|warn|warning|error|debug|log|critical|fatal|exception)\s*\(",
              "Registra eventos en el log"),
    Indicador("log_dato_sensible", "errores",
              r"\b(logger|log|LOGGER|LOG|logging|console)\.\w+\s*\([^)\n]*\b(password|passwd|token|secret|api_?key|credit|card|ssn|otp)\b",
              "Escribe datos sensibles en el log"),
    Indicador("log_entrada", "errores",
              r"\b(logger|log|LOGGER|LOG|logging|console)\.\w+\s*\([^)\n]*(req\.(body|query|params|headers)|request\.(args|form|get|"
              r"getParameter|json|headers)|getParameter|getHeader)",
              "Escribe datos de la petición en el log sin neutralizar"),
    # --- Configuración (archivos y código) ----------------------------------------------------
    Indicador("debug_activo", "config",
              r"\bdebug\s*[:=]\s*(true|True|1|on|yes)\b|\bDEBUG\s*=\s*(True|1|true)|app\.run\s*\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1|"
              r"FLASK_ENV\s*=\s*development|NODE_ENV\s*[=:]\s*['\"]?development|spring\.devtools|devtools\.restart|logging\.level\.\S+\s*[=:]\s*(DEBUG|TRACE)|"
              r"\bDEBUG\s*:\s*['\"]?(true|1)|show_sql\s*[:=]\s*true|-Xdebug|jdwp|--inspect",
              "Modo de depuración o trazas detalladas activas"),
    Indicador("cors_permisivo", "config",
              r"Access-Control-Allow-Origin['\"]?\s*[,:=]\s*['\"]\*|origin\s*:\s*(['\"]\*['\"]|true)|allow_origins\s*=\s*\[\s*['\"]\*|"
              r"allowedOrigins\s*\(\s*['\"]\*|allowed-origins\s*[:=]\s*['\"]?\*|@CrossOrigin\s*(\(\s*(origins\s*=\s*)?['\"]\*['\"]\s*\)|$|\n)|"
              r"\bcors\s*\(\s*\)|CORS\s*\(\s*app\s*\)|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|addAllowedOrigin\s*\(\s*['\"]\*|"
              r"allowedOriginPatterns\s*\(\s*['\"]\*|enableCors\s*\(\s*\)|Access-Control-Allow-Credentials['\"]?\s*[,:]\s*['\"]?true",
              "Política CORS que acepta cualquier origen"),
    Indicador("csrf_desactivado", "config",
              r"csrf\(\)\.disable\(\)|csrf\s*\(\s*\w*\s*->\s*\w*\.disable\(\)|csrf\(AbstractHttpConfigurer::disable\)|@csrf_exempt|"
              r"WTF_CSRF_ENABLED\s*=\s*False|csrf\s*[:=]\s*false",
              "Protección CSRF deshabilitada"),
    Indicador("cabeceras_seguridad", "config",
              r"\bhelmet\b|Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Talisman|"
              r"\.headers\s*\(\s*\w*\s*->|SECURE_HSTS|SECURE_SSL_REDIRECT",
              "Configura cabeceras de seguridad"),
    Indicador("actuator_expuesto", "config",
              r"management\.endpoints\.web\.exposure\.include\s*[=:]\s*['\"]?\*|exposure\s*:\s*\n\s*include\s*:\s*['\"]?\*|"
              r"include\s*:\s*['\"]\*['\"]|management\.endpoint\.(env|heapdump|shutdown|threaddump)\.enabled\s*[=:]\s*true|"
              r"management\.security\.enabled\s*[=:]\s*false|endpoints\.sensitive\s*[=:]\s*false|show-details\s*:\s*always|"
              r"management\.endpoint\.health\.show-details\s*=\s*always|shutdown\s*:\s*\n\s*enabled\s*:\s*true",
              "Endpoints de administración (Actuator) expuestos"),
    Indicador("documentacion_expuesta", "config",
              r"springdoc\.(swagger-ui|api-docs)\.enabled\s*[=:]\s*true|swagger-ui|SwaggerModule\.setup|swaggerUi\.(serve|setup)|"
              r"docs_url\s*=\s*['\"]|openapi_url\s*=\s*['\"]|redoc_url|@EnableSwagger|/v\d/api-docs|swagger\.json|enabled\s*:\s*true\s*#?\s*swagger",
              "Documentación interactiva de la API publicada"),
    Indicador("consola_bd", "config", r"h2\.console\.enabled\s*[=:]\s*true|h2-console|mongo-express|phpmyadmin|adminer",
              "Consola de base de datos expuesta"),
    Indicador("tls_desactivado", "config",
              r"ssl\.enabled\s*[=:]\s*false|sslmode\s*=\s*disable|useSSL\s*=\s*false|\bssl\s*:\s*false|\btls\s*:\s*false|requireSSL\s*=\s*false|"
              r"require_ssl\s*[=:]\s*false|SESSION_COOKIE_SECURE\s*=\s*False|secure\s*:\s*false|setSecure\s*\(\s*false|httpOnly\s*:\s*false|"
              r"setHttpOnly\s*\(\s*false|httponly\s*=\s*False|secure\s*=\s*False",
              "TLS o atributos de seguridad deshabilitados"),
    Indicador("contenedor_root", "config",
              r"^\s*USER\s+(root|0)\b|privileged\s*:\s*true|\buser\s*:\s*['\"]?(root|0)['\"]?\s*$|cap_add\s*:|SYS_ADMIN|NET_ADMIN|"
              r"network_mode\s*:\s*['\"]?host|pid\s*:\s*['\"]?host|ipc\s*:\s*['\"]?host|/var/run/docker\.sock|apparmor[:=]unconfined|"
              r"seccomp[:=]unconfined|--privileged|chmod\s+(-R\s+)?777|allowPrivilegeEscalation\s*:\s*true",
              "Contenedor o proceso con privilegios elevados"),
    Indicador("imagen_sin_version", "config",
              r"^\s*FROM\s+(--platform=\S+\s+)?[\w./-]+(:latest)?(\s+(AS|as)\s+\w+)?\s*$|^\s*image\s*:\s*['\"]?[\w./-]+(:latest)?['\"]?\s*$",
              "Imagen base sin versión fija (latest)"),
    Indicador("descarga_remota", "config",
              r"^\s*ADD\s+https?://|curl\s+[^|\n]*\|\s*(ba|z)?sh|wget\s+[^|\n]*\|\s*(ba|z)?sh|wget\s+[^\n]*-O-\s*\|\s*sh|"
              r"pip\s+install[^\n]*--trusted-host|npm\s+config\s+set\s+strict-ssl\s+false|--allow-unauthenticated|--no-check-certificate|"
              r"gpgcheck\s*=\s*0|apk\s+add[^\n]*--allow-untrusted|ADD\s+[^\n]*\.(tar|gz|tgz|zip)\s",
              "Descarga o instala componentes sin verificar su integridad"),
    Indicador("paquete_sin_version", "config",
              r"apt-get\s+install(?![^\n]*=\d)[^\n]*\s[a-z][\w.+-]+(\s|$)|apk\s+add(?![^\n]*=\d)[^\n]*\s[a-z][\w.+-]+(\s|$)|"
              r"pip\s+install(?![^\n]*(==|-r\s))[^\n]*\s[a-zA-Z][\w.-]+(\s|$)|npm\s+install\s+(-g\s+)?[a-z@][\w./-]+(\s|$)(?!.*@\d)|"
              r"['\"][@\w./-]+['\"]\s*:\s*['\"](\*|latest|x|>=?\s*\d[^'\"]*|\^?0\.\d[^'\"]*)['\"]|^[A-Za-z][\w.-]+\s*(>=?[^=\n]*)?$|"
              r"<version>\s*(LATEST|RELEASE|\[[^\]]*,\s*\))\s*</version>|-SNAPSHOT</version>",
              "Dependencia o paquete sin versión fijada"),
    Indicador("puerto_sensible", "config",
              r"^\s*-\s*['\"]?(0\.0\.0\.0:)?(5432|3306|27017|6379|9200|5005|9229|11211|2375|2376|5672|15672|9092|22):\d+['\"]?\s*$|"
              r"^\s*EXPOSE\s+(22|2375|5005|9229)\b",
              "Base de datos, broker o puerto de depuración publicado fuera del contenedor"),
    Indicador("sin_limites_recursos", "config",
              r"mem_limit|cpus\s*:|resources\s*:\s*\n\s*limits|pids_limit|ulimits|deploy\s*:\s*\n\s*resources|memory\s*:\s*\d|healthcheck\s*:|HEALTHCHECK",
              "Define límites de recursos o comprobaciones de salud"),
    Indicador("openapi_sin_seguridad", "config",
              r"security\s*:\s*\[\s*\]|security\s*:\s*\n\s*-\s*\{\s*\}|securitySchemes\s*:\s*\{\s*\}|type\s*:\s*['\"]?http['\"]?\s*\n\s*scheme\s*:\s*['\"]?basic|"
              r"\bin\s*:\s*['\"]?query['\"]?\s*\n?\s*(name\s*:\s*['\"]?(api_?key|token|access_token))|flow\s*:\s*['\"]?(implicit|password)|"
              r"type\s*:\s*['\"]?basic",
              "Especificación OpenAPI sin seguridad o con autenticación débil"),
    Indicador("openapi_propiedades_abiertas", "config",
              r"additionalProperties\s*:\s*true|readOnly\s*:\s*false|writeOnly\s*:\s*false",
              "Esquema OpenAPI que acepta propiedades no declaradas"),
    Indicador("openapi_sin_limites", "config", r"type\s*:\s*['\"]?(string|array|integer)['\"]?\s*$",
              "Tipos de la especificación (se compara con los límites declarados)"),
    Indicador("api_obsoleta", "config", r"deprecated\s*:\s*true|@Deprecated|/v0/|/beta/|/old/|/legacy/|/test/|/staging|/dev/|"
              r"url\s*:\s*['\"]?https?://[^'\"\s]*(dev|staging|test|qa|beta|old)[.-]",
              "Versión o endpoint obsoleto, de pruebas o heredado expuesto"),
]

COMPILADOS = [(ind, ind.compilar()) for ind in INDICADORES]
NOMBRES_INDICADORES = [i.nombre for i in INDICADORES]
INDICE = {n: k for k, n in enumerate(NOMBRES_INDICADORES)}
DESCRIPCION = {i.nombre: i.descripcion for i in INDICADORES}
FAMILIA = {i.nombre: i.familia for i in INDICADORES}

# Indicadores que se evalúan también sobre el contexto (clase / archivo)
CONTEXTO = ["guard_autenticacion", "verificacion_rol", "acceso_publico", "limite_frecuencia", "validacion_entrada"]

SUBTIPOS = ["codigo", "dockerfile", "compose", "yaml", "properties", "env", "openapi", "manifiesto"]
LENGUAJES = ["java", "python", "javascript", "typescript", "config"]


def _contar(texto):
    return np.array([len(rx.findall(texto)) for _, rx in COMPILADOS], dtype=float)


def _metricas(texto):
    lineas = [l for l in texto.splitlines() if l.strip()]
    n = max(len(lineas), 1)
    sangrias = [len(l) - len(l.lstrip()) for l in lineas] or [0]
    concat = len(re.findall(r"[\"'`]\s*\+\s*\w|\w\s*\+\s*[\"'`]", texto))
    interp = len(re.findall(r"\$\{|\bf[\"']|%s|\{\w*\}[\"']\s*\.format|String\.format", texto))
    return np.array([
        np.log1p(n),
        np.log1p(len(texto)),
        np.log1p(len(re.findall(r"[\"'`]", texto)) / 2),
        np.log1p(concat),
        np.log1p(interp),
        np.log1p(len(re.findall(r"\w\s*\(", texto))),
        np.log1p(len(re.findall(r"\bif\b|\?\s*\w", texto))),
        np.log1p(len(re.findall(r"\breturn\b", texto))),
        np.log1p((max(sangrias) - min(sangrias)) / 2),
        np.log1p(sum(len(l) for l in lineas) / n),
    ], dtype=float)


NOMBRES_METRICAS = ["m_lineas", "m_caracteres", "m_cadenas", "m_concatenaciones", "m_interpolaciones", "m_llamadas",
                    "m_condicionales", "m_retornos", "m_profundidad", "m_longitud_media"]


def _derivadas(c, ctx, subtipo):
    """Interacciones fuente->operación y ausencias de control (variables que el modelo pondera)."""
    g = lambda n: c[INDICE[n]] > 0  # noqa: E731
    gc = lambda n: ctx[CONTEXTO.index(n)] > 0  # noqa: E731
    entrada = g("entrada_http") or g("parametro_ruta_id") or g("entrada_otros")
    ruta = g("ruta_definida")
    guard = g("guard_autenticacion") or gc("guard_autenticacion")
    rol = g("verificacion_rol") or gc("verificacion_rol")
    es_config = subtipo != "codigo"
    v = [
        entrada and g("sql_dinamico"),
        entrada and (g("ejecucion_comando")),
        entrada and g("eval_dinamico"),
        entrada and g("acceso_archivo") and not g("ruta_normalizada"),
        entrada and g("peticion_saliente") and not g("lista_blanca"),
        entrada and g("html_sin_escape") and not g("escape_salida"),
        entrada and g("deserializacion"),
        entrada and g("redireccion") and not g("lista_blanca"),
        entrada and g("xml_parser") and not g("xml_protegido"),
        entrada and g("nosql_dinamico"),
        ruta and g("parametro_ruta_id") and g("busqueda_por_id") and not g("verificacion_propiedad"),
        ruta and g("busqueda_por_id") and g("usuario_actual") and not g("verificacion_propiedad"),
        ruta and not guard and not g("acceso_publico") and not g("ruta_autenticacion"),
        ruta and (g("ruta_administrativa") or g("metodo_modificacion")) and not rol,
        ruta and g("ruta_administrativa") and not rol and not guard,
        g("asignacion_masiva") and not g("filtro_propiedades"),
        g("respuesta_objeto") and g("datos_sensibles") and not g("filtro_propiedades"),
        ruta and g("consulta_coleccion") and not g("paginacion"),
        ruta and g("ruta_autenticacion") and not (g("limite_frecuencia") or gc("limite_frecuencia") or g("limite_intentos")),
        g("subida_archivo") and not g("limite_tamano"),
        g("peticion_saliente") and not g("timeout"),
        g("peticion_saliente") and g("respuesta_externa_usada") and not g("validacion_entrada"),
        g("jwt") and g("jwt_inseguro"),
        g("secreto_literal") and not g("secreto_externo"),
        g("manejo_excepciones") and g("error_expuesto"),
        ruta and entrada and not g("validacion_entrada"),
        es_config and subtipo == "openapi" and c[INDICE["openapi_sin_limites"]] > 0 and not g("limite_tamano"),
        g("recurso_de_usuario") and g("parametro_ruta_id") and g("busqueda_por_id") and not g("verificacion_propiedad"),
        g("aleatorio_debil") and g("datos_sensibles"),
    ]
    return np.array(v, dtype=float)


NOMBRES_DERIVADAS = [
    "x_entrada_sql", "x_entrada_comando", "x_entrada_eval", "x_entrada_archivo_sin_normalizar", "x_entrada_peticion_sin_lista",
    "x_entrada_html_sin_escape", "x_entrada_deserializacion", "x_entrada_redireccion", "x_entrada_xml", "x_entrada_nosql",
    "x_id_ruta_sin_propiedad", "x_usuario_sin_propiedad", "x_ruta_sin_autenticacion", "x_ruta_privilegiada_sin_rol",
    "x_ruta_admin_sin_control", "x_asignacion_sin_filtro", "x_objeto_sensible_sin_filtro", "x_coleccion_sin_paginacion",
    "x_login_sin_limite", "x_subida_sin_limite", "x_peticion_sin_timeout", "x_respuesta_externa_sin_validar", "x_jwt_inseguro",
    "x_secreto_sin_gestor", "x_error_expuesto", "x_entrada_sin_validar", "x_openapi_sin_limites",
    "x_recurso_propio_sin_propiedad", "x_aleatorio_sensible",
]


def _por_archivo(unidad):
    """Variables propias del tipo de archivo (meta de la segmentación)."""
    meta = unidad.meta or {}
    return np.array([
        float(unidad.subtipo == "dockerfile" and not meta.get("archivo_tiene_user", True) and meta.get("ultima_etapa", True)),
        float(bool(meta.get("lineas_aproximadas"))),
    ])


NOMBRES_ARCHIVO = ["a_dockerfile_sin_usuario", "a_lineas_aproximadas"]


def nombres_caracteristicas():
    return (NOMBRES_INDICADORES + [f"ctx_{n}" for n in CONTEXTO] + NOMBRES_DERIVADAS + NOMBRES_METRICAS + NOMBRES_ARCHIVO +
            [f"sub_{s}" for s in SUBTIPOS] + [f"len_{l}" for l in LENGUAJES])


# Métricas que describen el estilo del código (no la seguridad); pueden desactivarse.
METRICAS_ESTILO = ["m_cadenas", "m_llamadas", "m_condicionales", "m_retornos", "m_profundidad", "m_longitud_media"]
_IDX_ESTILO = [NOMBRES_METRICAS.index(n) for n in METRICAS_ESTILO]


def vector(unidad, binario=False, estilo=True):
    """Vector numérico de características de una unidad.

    binario: indicadores como presencia (0/1) en lugar de log(1 + número de apariciones).
    estilo:  incluir las métricas de estilo del código; si es False se fijan en 0 (misma dimensión).
    """
    from .lexico import limpiar_codigo

    texto = limpiar_codigo(unidad.texto)
    c = _contar(texto)
    ctx_txt = unidad.contexto or ""
    ctx = np.array([len(COMPILADOS[INDICE[n]][1].findall(ctx_txt)) for n in CONTEXTO], dtype=float)
    d = _derivadas(c, ctx, unidad.subtipo)
    m = _metricas(texto)
    if not estilo:
        m[_IDX_ESTILO] = 0.0
    a = _por_archivo(unidad)
    sub = np.array([float(unidad.subtipo == s) for s in SUBTIPOS])
    leng = np.array([float(unidad.lenguaje == l) for l in LENGUAJES])
    transformar = (lambda x: (x > 0).astype(float)) if binario else np.log1p
    return np.concatenate([transformar(c), transformar(ctx), d, m, a, sub, leng])


# Familias que describen el contexto (fuentes de entrada, rutas, validación, autenticación) y no una
# operación peligrosa.
FAMILIAS_CONTEXTO = {"entrada", "rutas", "validacion", "auth"}
_MASCARA_EVIDENCIA = np.array([(n in FAMILIA and FAMILIA[n] not in FAMILIAS_CONTEXTO) or n.startswith("x_")
                               for n in nombres_caracteristicas()])


def puntaje_evidencia(unidad):
    """Cantidad de indicadores de operación peligrosa y de patrones combinados activos en la unidad."""
    return float((vector(unidad, binario=True, estilo=False)[_MASCARA_EVIDENCIA] > 0).sum())


def evidencias(unidad, nombres=None, max_por_indicador=3):
    """Líneas donde se activan los indicadores: [(indicador, línea, texto)]."""
    salida = []
    lineas = unidad.texto.splitlines()
    for ind, rx in COMPILADOS:
        if nombres and ind.nombre not in nombres:
            continue
        k = 0
        for i, linea in enumerate(lineas):
            if rx.search(linea):
                salida.append((ind.nombre, unidad.lineas[i] if i < len(unidad.lineas) else unidad.linea_inicio, linea.strip()))
                k += 1
                if k >= max_por_indicador:
                    break
    return salida


def consume_api(texto):
    """True si el fragmento consume otra API (para relaciones de contexto CWE -> API10)."""
    return bool(COMPILADOS[INDICE["peticion_saliente"]][1].search(texto))

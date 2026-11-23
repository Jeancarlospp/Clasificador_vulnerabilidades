"""Casos controlados en estilo de producción (complemento de generar_casos_controlados.py).

Los ejemplos de las pruebas de reglas son fragmentos cortos que aíslan la vulnerabilidad. En un
microservicio real, la línea vulnerable está rodeada de código normal: inyección de servicios, logs,
validaciones de otros campos, mapeo a DTO, manejo de excepciones. Estas plantillas reproducen ese
estilo para que el modelo no asocie "código largo y ordenado" con "código seguro".

Cada familia tiene pares vulnerable / corregido que difieren en el control de seguridad. Las
plantillas son originales (no se copian de los proyectos usados en la evaluación).
"""

# (framework, estilo, extensión, ancla, vulnerable, texto)
PRODUCCION = {}

# ---------------------------------------------------------------------------------------------
# API1 — BOLA en capas de servicio
# ---------------------------------------------------------------------------------------------
PRODUCCION["bola"] = [
    ("spring", "c", "java", "public ResponseEntity<{Ent}Response> get{Ent}", 1, """package com.acme.{ents}.web;

import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/{ents}")
public class {Ent}QueryController {{

    private static final Logger log = LoggerFactory.getLogger({Ent}QueryController.class);
    private final {Ent}Service {ent}Service;
    private final {Ent}Mapper mapper;

    public {Ent}QueryController({Ent}Service {ent}Service, {Ent}Mapper mapper) {{
        this.{ent}Service = {ent}Service;
        this.mapper = mapper;
    }}

    @GetMapping("/{{{idv}}}")
    public ResponseEntity<{Ent}Response> get{Ent}(@PathVariable UUID {idv}) {{
        log.info("Fetching {ent} {{}}", {idv});
        {Ent} {ent} = {ent}Service.findById({idv})
                .orElseThrow(() -> new NotFoundException("{Ent} not found"));
        {Ent}Response body = mapper.toResponse({ent});
        body.setRetrievedAt(Instant.now());
        return ResponseEntity.ok(body);
    }}
}}
"""),
    ("spring", "c", "java", "public ResponseEntity<{Ent}Response> get{Ent}", 0, """package com.acme.{ents}.web;

import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/{ents}")
public class {Ent}QueryController {{

    private static final Logger log = LoggerFactory.getLogger({Ent}QueryController.class);
    private final {Ent}Service {ent}Service;
    private final {Ent}Mapper mapper;

    public {Ent}QueryController({Ent}Service {ent}Service, {Ent}Mapper mapper) {{
        this.{ent}Service = {ent}Service;
        this.mapper = mapper;
    }}

    @GetMapping("/{{{idv}}}")
    public ResponseEntity<{Ent}Response> get{Ent}(@PathVariable UUID {idv}, @AuthenticationPrincipal AppUser currentUser) {{
        log.info("Fetching {ent} {{}}", {idv});
        {Ent} {ent} = {ent}Service.findByIdAndOwnerId({idv}, currentUser.getId())
                .orElseThrow(() -> new NotFoundException("{Ent} not found"));
        {Ent}Response body = mapper.toResponse({ent});
        body.setRetrievedAt(Instant.now());
        return ResponseEntity.ok(body);
    }}
}}
"""),
    ("drf", "c", "py", "def get(self, request, pk", 1, """import logging

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import {Ent}
from .serializers import {Ent}Serializer

logger = logging.getLogger(__name__)


class {Ent}DetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        logger.debug("detail requested for {ent} %s", pk)
        try:
            {ent} = {Ent}.objects.select_related("customer").get(pk=pk)
        except {Ent}.DoesNotExist:
            return Response({{"detail": "not found"}}, status=status.HTTP_404_NOT_FOUND)
        serializer = {Ent}Serializer({ent})
        return Response(serializer.data, status=status.HTTP_200_OK)
"""),
    ("drf", "c", "py", "def get(self, request, pk", 0, """import logging

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import {Ent}
from .serializers import {Ent}Serializer

logger = logging.getLogger(__name__)


class {Ent}DetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None):
        logger.debug("detail requested for {ent} %s", pk)
        try:
            {ent} = {Ent}.objects.select_related("customer").get(pk=pk, {own_py}=request.user.id)
        except {Ent}.DoesNotExist:
            return Response({{"detail": "not found"}}, status=status.HTTP_404_NOT_FOUND)
        serializer = {Ent}Serializer({ent})
        return Response(serializer.data, status=status.HTTP_200_OK)
"""),
    ("nest", "c", "ts", "async getOne(", 1, """import {{ Controller, Get, Logger, NotFoundException, Param, ParseUUIDPipe, UseGuards }} from '@nestjs/common';
import {{ JwtAuthGuard }} from '../auth/guards/jwt-auth.guard';
import {{ {Ent}Service }} from './{ent}.service';
import {{ {Ent}Dto }} from './dto/{ent}.dto';

@Controller('{ents}')
@UseGuards(JwtAuthGuard)
export class {Ent}Controller {{
  private readonly logger = new Logger({Ent}Controller.name);

  constructor(private readonly {ent}Service: {Ent}Service) {{}}

  @Get(':{idv}')
  async getOne(@Param('{idv}', ParseUUIDPipe) {idv}: string): Promise<{Ent}Dto> {{
    this.logger.log(`loading {ent} ${{{idv}}}`);
    const {ent} = await this.{ent}Service.findOne({{ where: {{ id: {idv} }}, relations: ['items'] }});
    if (!{ent}) {{
      throw new NotFoundException();
    }}
    return {Ent}Dto.fromEntity({ent});
  }}
}}
"""),
    ("nest", "c", "ts", "async getOne(", 0, """import {{ Controller, Get, Logger, NotFoundException, Param, ParseUUIDPipe, UseGuards }} from '@nestjs/common';
import {{ JwtAuthGuard }} from '../auth/guards/jwt-auth.guard';
import {{ CurrentUser }} from '../auth/decorators/current-user.decorator';
import {{ {Ent}Service }} from './{ent}.service';
import {{ {Ent}Dto }} from './dto/{ent}.dto';

@Controller('{ents}')
@UseGuards(JwtAuthGuard)
export class {Ent}Controller {{
  private readonly logger = new Logger({Ent}Controller.name);

  constructor(private readonly {ent}Service: {Ent}Service) {{}}

  @Get(':{idv}')
  async getOne(@Param('{idv}', ParseUUIDPipe) {idv}: string, @CurrentUser() user: AuthUser): Promise<{Ent}Dto> {{
    this.logger.log(`loading {ent} ${{{idv}}}`);
    const {ent} = await this.{ent}Service.findOne({{ where: {{ id: {idv}, {own}: user.id }}, relations: ['items'] }});
    if (!{ent}) {{
      throw new NotFoundException();
    }}
    return {Ent}Dto.fromEntity({ent});
  }}
}}
"""),
    ("express", "c", "js", "async function get{Ent}(req, res, next)", 1, """const {{ {Ent} }} = require('../models');
const logger = require('../config/logger');
const httpStatus = require('http-status');

async function get{Ent}(req, res, next) {{
  try {{
    const {idv} = req.params.{idv};
    logger.info(`get {ent} ${{{idv}}}`);
    const {ent} = await {Ent}.findByPk({idv}, {{ include: ['lines'] }});
    if (!{ent}) {{
      return res.status(httpStatus.NOT_FOUND).json({{ message: '{Ent} not found' }});
    }}
    return res.status(httpStatus.OK).json({ent}.toJSON());
  }} catch (error) {{
    return next(error);
  }}
}}

module.exports = {{ get{Ent} }};
"""),
    ("express", "c", "js", "async function get{Ent}(req, res, next)", 0, """const {{ {Ent} }} = require('../models');
const logger = require('../config/logger');
const httpStatus = require('http-status');

async function get{Ent}(req, res, next) {{
  try {{
    const {idv} = req.params.{idv};
    logger.info(`get {ent} ${{{idv}}}`);
    const {ent} = await {Ent}.findOne({{ where: {{ id: {idv}, {own}: req.user.id }}, include: ['lines'] }});
    if (!{ent}) {{
      return res.status(httpStatus.NOT_FOUND).json({{ message: '{Ent} not found' }});
    }}
    return res.status(httpStatus.OK).json({ent}.toJSON());
  }} catch (error) {{
    return next(error);
  }}
}}

module.exports = {{ get{Ent} }};
"""),
    ("fastapi", "c", "py", "async def get_{ent}_detail(", 1, """import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_active_user, get_session
from app.models import {Ent}, User
from app.schemas.{ent} import {Ent}Read

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/{ents}", tags=["{ents}"])


@router.get("/{{{idv_py}}}", response_model={Ent}Read)
async def get_{ent}_detail(
    {idv_py}: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_active_user),
):
    logger.info("user %s requested {ent} %s", current_user.id, {idv_py})
    {ent} = await session.get({Ent}, {idv_py})
    if {ent} is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="{Ent} not found")
    return {ent}
"""),
    ("fastapi", "c", "py", "async def get_{ent}_detail(", 0, """import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_active_user, get_session
from app.models import {Ent}, User
from app.schemas.{ent} import {Ent}Read

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/{ents}", tags=["{ents}"])


@router.get("/{{{idv_py}}}", response_model={Ent}Read)
async def get_{ent}_detail(
    {idv_py}: UUID,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_active_user),
):
    logger.info("user %s requested {ent} %s", current_user.id, {idv_py})
    {ent} = await session.get({Ent}, {idv_py})
    if {ent} is None or {ent}.{own_py} != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="{Ent} not found")
    return {ent}
"""),
]

# ---------------------------------------------------------------------------------------------
# API5 — BFLA: operaciones administrativas protegidas solo con autenticación
# ---------------------------------------------------------------------------------------------
PRODUCCION["bfla"] = [
    ("drf", "c", "py", "class {Ent}ApprovalView(", 1, """from django.db import transaction
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import {Ent}
from .services import notify_customer


class {Ent}ApprovalView(APIView):
    permission_classes = [IsAuthenticated]

    @transaction.atomic
    def post(self, request, pk=None):
        {ent} = {Ent}.objects.select_for_update().get(pk=pk)
        {ent}.status = {Ent}.Status.APPROVED
        {ent}.approved_by = request.user
        {ent}.save(update_fields=["status", "approved_by"])
        notify_customer({ent})
        return Response({{"status": {ent}.status}}, status=status.HTTP_200_OK)
"""),
    ("drf", "c", "py", "class {Ent}ApprovalView(", 0, """from django.db import transaction
from rest_framework import status
from rest_framework.permissions import IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import {Ent}
from .services import notify_customer


class {Ent}ApprovalView(APIView):
    permission_classes = [IsAuthenticated, IsAdminUser]

    @transaction.atomic
    def post(self, request, pk=None):
        {ent} = {Ent}.objects.select_for_update().get(pk=pk)
        {ent}.status = {Ent}.Status.APPROVED
        {ent}.approved_by = request.user
        {ent}.save(update_fields=["status", "approved_by"])
        notify_customer({ent})
        return Response({{"status": {ent}.status}}, status=status.HTTP_200_OK)
"""),
    ("spring", "c", "java", "public ResponseEntity<Void> disableAccount", 1, """@RestController
@RequestMapping("/api/v1/admin/accounts")
@RequiredArgsConstructor
public class AccountAdminController {{

    private final AccountService accountService;
    private final AuditService auditService;

    @PostMapping("/{{accountId}}/disable")
    public ResponseEntity<Void> disableAccount(@PathVariable Long accountId, Authentication authentication) {{
        accountService.disable(accountId);
        auditService.record("ACCOUNT_DISABLED", accountId, authentication.getName());
        return ResponseEntity.noContent().build();
    }}
}}
"""),
    ("spring", "c", "java", "public ResponseEntity<Void> disableAccount", 0, """@RestController
@RequestMapping("/api/v1/admin/accounts")
@RequiredArgsConstructor
public class AccountAdminController {{

    private final AccountService accountService;
    private final AuditService auditService;

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/{{accountId}}/disable")
    public ResponseEntity<Void> disableAccount(@PathVariable Long accountId, Authentication authentication) {{
        accountService.disable(accountId);
        auditService.record("ACCOUNT_DISABLED", accountId, authentication.getName());
        return ResponseEntity.noContent().build();
    }}
}}
"""),
    ("nest", "c", "ts", "async purge(", 1, """@Controller('admin/{ents}')
@UseGuards(JwtAuthGuard)
export class {Ent}AdminController {{
  constructor(
    private readonly {ent}Service: {Ent}Service,
    private readonly auditLog: AuditLogService,
  ) {{}}

  @Delete('purge')
  @HttpCode(204)
  async purge(@Query('before') before: string, @Req() req: Request) {{
    const deleted = await this.{ent}Service.deleteOlderThan(new Date(before));
    await this.auditLog.write('{ents}.purge', {{ actor: req.user['sub'], deleted }});
  }}
}}
"""),
    ("nest", "c", "ts", "async purge(", 0, """@Controller('admin/{ents}')
@UseGuards(JwtAuthGuard, RolesGuard)
export class {Ent}AdminController {{
  constructor(
    private readonly {ent}Service: {Ent}Service,
    private readonly auditLog: AuditLogService,
  ) {{}}

  @Delete('purge')
  @Roles(Role.Admin)
  @HttpCode(204)
  async purge(@Query('before') before: string, @Req() req: Request) {{
    const deleted = await this.{ent}Service.deleteOlderThan(new Date(before));
    await this.auditLog.write('{ents}.purge', {{ actor: req.user['sub'], deleted }});
  }}
}}
"""),
]

# ---------------------------------------------------------------------------------------------
# API3 — asignación masiva en serializadores, entidades y documentos
# ---------------------------------------------------------------------------------------------
PRODUCCION["asignacion_masiva"] = [
    ("drf", "c", "py", "        fields = ", 1, """from rest_framework import serializers

from .models import {Ent}


class {Ent}UpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = {Ent}
        fields = "__all__"

    def validate_quantity(self, value):
        if value < 1:
            raise serializers.ValidationError("quantity must be positive")
        return value
"""),
    ("drf", "c", "py", "        fields = ", 0, """from rest_framework import serializers

from .models import {Ent}


class {Ent}UpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = {Ent}
        fields = ["quantity", "notes"]
        read_only_fields = ["status", "price", "owner"]

    def validate_quantity(self, value):
        if value < 1:
            raise serializers.ValidationError("quantity must be positive")
        return value
"""),
    ("express", "c", "js", "async function update{Ent}(req, res)", 1, """const {Ent} = require('../models/{ent}.model');
const ApiError = require('../utils/ApiError');

async function update{Ent}(req, res) {{
  const {ent} = await {Ent}.findOne({{ _id: req.params.{idv}, {own}: req.user.id }});
  if (!{ent}) {{
    throw new ApiError(404, '{Ent} not found');
  }}
  const updated = await {Ent}.findByIdAndUpdate({ent}.id, req.body, {{ new: true, runValidators: true }});
  res.send(updated);
}}

module.exports = {{ update{Ent} }};
"""),
    ("express", "c", "js", "async function update{Ent}(req, res)", 0, """const pick = require('../utils/pick');
const {Ent} = require('../models/{ent}.model');
const ApiError = require('../utils/ApiError');

async function update{Ent}(req, res) {{
  const {ent} = await {Ent}.findOne({{ _id: req.params.{idv}, {own}: req.user.id }});
  if (!{ent}) {{
    throw new ApiError(404, '{Ent} not found');
  }}
  const changes = pick(req.body, ['title', 'description', 'quantity']);
  const updated = await {Ent}.findByIdAndUpdate({ent}.id, changes, {{ new: true, runValidators: true }});
  res.send(updated);
}}

module.exports = {{ update{Ent} }};
"""),
    ("spring", "c", "java", "public UserResponse updateProfile", 1, """@RestController
@RequestMapping("/api/v1/profile")
@RequiredArgsConstructor
public class ProfileController {{

    private final UserRepository users;

    @PutMapping
    @Transactional
    public UserResponse updateProfile(@RequestBody User incoming, Principal principal) {{
        User user = users.findByEmail(principal.getName()).orElseThrow();
        incoming.setId(user.getId());
        User saved = users.save(incoming);
        return UserResponse.from(saved);
    }}
}}
"""),
    ("spring", "c", "java", "public UserResponse updateProfile", 0, """@RestController
@RequestMapping("/api/v1/profile")
@RequiredArgsConstructor
public class ProfileController {{

    private final UserRepository users;

    @PutMapping
    @Transactional
    public UserResponse updateProfile(@Valid @RequestBody ProfileUpdateRequest incoming, Principal principal) {{
        User user = users.findByEmail(principal.getName()).orElseThrow();
        user.setDisplayName(incoming.displayName());
        user.setPhone(incoming.phone());
        User saved = users.save(user);
        return UserResponse.from(saved);
    }}
}}
"""),
]

# ---------------------------------------------------------------------------------------------
# A05 — inyección SQL y de comandos en capas de datos y utilidades
# ---------------------------------------------------------------------------------------------
PRODUCCION["sqli"] = [
    ("spring", "c", "java", "public List<{Ent}Summary> search", 1, """@Repository
@RequiredArgsConstructor
public class {Ent}SearchRepository {{

    private final JdbcTemplate jdbcTemplate;
    private final {Ent}RowMapper rowMapper;

    public List<{Ent}Summary> search(String customerId, String status, int limit) {{
        String sql = "SELECT id, total, status FROM {ents} WHERE customer_id = '" + customerId
                + "' AND status = '" + status + "' ORDER BY created_at DESC";
        return jdbcTemplate.query(sql, rowMapper).stream().limit(limit).toList();
    }}
}}
"""),
    ("spring", "c", "java", "public List<{Ent}Summary> search", 0, """@Repository
@RequiredArgsConstructor
public class {Ent}SearchRepository {{

    private final JdbcTemplate jdbcTemplate;
    private final {Ent}RowMapper rowMapper;

    public List<{Ent}Summary> search(String customerId, String status, int limit) {{
        String sql = "SELECT id, total, status FROM {ents} WHERE customer_id = ? AND status = ? ORDER BY created_at DESC";
        return jdbcTemplate.query(sql, rowMapper, customerId, status).stream().limit(limit).toList();
    }}
}}
"""),
    ("drf", "c", "py", "def post(self, request", 1, """from django.db import connection
from rest_framework.response import Response
from rest_framework.views import APIView


class ApplyDiscountView(APIView):
    def post(self, request, *args, **kwargs):
        code = request.data.get("code", "").strip()
        if not code:
            return Response({{"error": "code required"}}, status=400)
        with connection.cursor() as cursor:
            cursor.execute("SELECT amount FROM discounts WHERE code = '" + code + "' AND active = true")
            row = cursor.fetchone()
        if row is None:
            return Response({{"error": "invalid code"}}, status=404)
        return Response({{"amount": row[0]}})
"""),
    ("drf", "c", "py", "def post(self, request", 0, """from django.db import connection
from rest_framework.response import Response
from rest_framework.views import APIView


class ApplyDiscountView(APIView):
    def post(self, request, *args, **kwargs):
        code = request.data.get("code", "").strip()
        if not code:
            return Response({{"error": "code required"}}, status=400)
        with connection.cursor() as cursor:
            cursor.execute("SELECT amount FROM discounts WHERE code = %s AND active = true", [code])
            row = cursor.fetchone()
        if row is None:
            return Response({{"error": "invalid code"}}, status=404)
        return Response({{"amount": row[0]}})
"""),
    ("nest", "c", "ts", "async findByReference(", 1, """@Injectable()
export class {Ent}Repository {{
  constructor(@InjectDataSource() private readonly dataSource: DataSource) {{}}

  async findByReference(reference: string, tenantId: string): Promise<{Ent}Row[]> {{
    const rows = await this.dataSource.query(
      `SELECT * FROM {ents} WHERE reference = '${{reference}}' AND tenant_id = '${{tenantId}}'`,
    );
    return rows.map((r) => new {Ent}Row(r));
  }}
}}
"""),
    ("nest", "c", "ts", "async findByReference(", 0, """@Injectable()
export class {Ent}Repository {{
  constructor(@InjectDataSource() private readonly dataSource: DataSource) {{}}

  async findByReference(reference: string, tenantId: string): Promise<{Ent}Row[]> {{
    const rows = await this.dataSource.query(
      'SELECT * FROM {ents} WHERE reference = $1 AND tenant_id = $2',
      [reference, tenantId],
    );
    return rows.map((r) => new {Ent}Row(r));
  }}
}}
"""),
    ("fastapi", "c", "py", "async def search_{ents}(", 1, """@router.get("/search")
async def search_{ents}(q: str, session: AsyncSession = Depends(get_session), user=Depends(get_current_user)):
    logger.info("search by %s", user.id)
    result = await session.execute(text(f"SELECT id, name FROM {ents} WHERE name ILIKE '%{{q}}%' LIMIT 20"))
    return [dict(r._mapping) for r in result]
"""),
    ("fastapi", "c", "py", "async def search_{ents}(", 0, """@router.get("/search")
async def search_{ents}(q: str, session: AsyncSession = Depends(get_session), user=Depends(get_current_user)):
    logger.info("search by %s", user.id)
    result = await session.execute(text("SELECT id, name FROM {ents} WHERE name ILIKE :q LIMIT 20"), {{"q": f"%{{q}}%"}})
    return [dict(r._mapping) for r in result]
"""),
]

PRODUCCION["cmdi"] = [
    ("fastapi", "c", "py", "def run_diagnostics(", 1, """@router.get("/diagnostics/ping")
def run_diagnostics(host: str, admin=Depends(get_current_admin)):
    logger.warning("diagnostics requested by %s", admin.id)
    output = subprocess.run(f"ping -c 2 {{host}}", shell=True, capture_output=True, text=True, timeout=10)
    return {{"returncode": output.returncode, "stdout": output.stdout}}
"""),
    ("fastapi", "c", "py", "def run_diagnostics(", 0, """@router.get("/diagnostics/ping")
def run_diagnostics(host: str, admin=Depends(get_current_admin)):
    logger.warning("diagnostics requested by %s", admin.id)
    if not HOSTNAME_RE.fullmatch(host):
        raise HTTPException(status_code=400, detail="invalid host")
    output = subprocess.run(["ping", "-c", "2", host], capture_output=True, text=True, timeout=10)
    return {{"returncode": output.returncode, "stdout": output.stdout}}
"""),
    ("spring", "c", "java", "public String convert", 1, """@Service
@Slf4j
public class MediaConversionService {{

    public String convert(String inputFile, String options) throws IOException, InterruptedException {{
        log.info("converting {{}}", inputFile);
        Process process = new ProcessBuilder("sh", "-c", "ffmpeg -i " + inputFile + " " + options + " out.mp4")
                .redirectErrorStream(true)
                .start();
        process.waitFor(30, TimeUnit.SECONDS);
        return new String(process.getInputStream().readAllBytes());
    }}
}}
"""),
    ("spring", "c", "java", "public String convert", 0, """@Service
@Slf4j
public class MediaConversionService {{

    public String convert(String inputFile, ConversionPreset preset) throws IOException, InterruptedException {{
        log.info("converting {{}}", inputFile);
        Process process = new ProcessBuilder("ffmpeg", "-i", inputFile, "-preset", preset.value(), "out.mp4")
                .redirectErrorStream(true)
                .start();
        process.waitFor(30, TimeUnit.SECONDS);
        return new String(process.getInputStream().readAllBytes());
    }}
}}
"""),
    ("express", "c", "js", "router.post('/tools/archive'", 1, """router.post('/tools/archive', authenticate, async (req, res, next) => {{
  try {{
    const {{ folder }} = req.body;
    const target = `/tmp/archives/${{Date.now()}}.tar.gz`;
    await execAsync(`tar -czf ${{target}} ${{folder}}`);
    res.json({{ archive: target }});
  }} catch (err) {{
    next(err);
  }}
}});
"""),
    ("express", "c", "js", "router.post('/tools/archive'", 0, """router.post('/tools/archive', authenticate, async (req, res, next) => {{
  try {{
    const folder = path.basename(req.body.folder || '');
    const target = `/tmp/archives/${{Date.now()}}.tar.gz`;
    await execFileAsync('tar', ['-czf', target, '-C', BASE_DIR, folder]);
    res.json({{ archive: target }});
  }} catch (err) {{
    next(err);
  }}
}});
"""),
]

# ---------------------------------------------------------------------------------------------
# A01 — path traversal en descargas
# ---------------------------------------------------------------------------------------------
PRODUCCION["path_traversal"] = [
    ("express", "c", "js", "router.get('/{ents}/files/:name'", 1, """router.get('/{ents}/files/:name', authenticate, (req, res, next) => {{
  const filePath = path.join(UPLOAD_DIR, req.params.name);
  fs.access(filePath, fs.constants.R_OK, (err) => {{
    if (err) return res.status(404).json({{ message: 'not found' }});
    return res.sendFile(filePath);
  }});
}});
"""),
    ("express", "c", "js", "router.get('/{ents}/files/:name'", 0, """router.get('/{ents}/files/:name', authenticate, (req, res, next) => {{
  const filePath = path.resolve(UPLOAD_DIR, path.basename(req.params.name));
  if (!filePath.startsWith(path.resolve(UPLOAD_DIR) + path.sep)) return res.status(400).end();
  fs.access(filePath, fs.constants.R_OK, (err) => {{
    if (err) return res.status(404).json({{ message: 'not found' }});
    return res.sendFile(filePath);
  }});
}});
"""),
    ("fastapi", "c", "py", "def download_attachment(", 1, """@router.get("/attachments/{{filename}}")
def download_attachment(filename: str, user=Depends(get_current_user)):
    path = os.path.join(settings.ATTACHMENTS_DIR, filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404)
    return FileResponse(path)
"""),
    ("fastapi", "c", "py", "def download_attachment(", 0, """@router.get("/attachments/{{filename}}")
def download_attachment(filename: str, user=Depends(get_current_user)):
    base = Path(settings.ATTACHMENTS_DIR).resolve()
    path = (base / filename).resolve()
    if not path.is_relative_to(base) or not path.exists():
        raise HTTPException(status_code=404)
    return FileResponse(path)
"""),
    ("spring", "c", "java", "public ResponseEntity<Resource> download", 1, """@GetMapping("/reports/{{name}}")
public ResponseEntity<Resource> download(@PathVariable String name) throws IOException {{
    Path file = Paths.get(reportsDir, name);
    Resource resource = new UrlResource(file.toUri());
    return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + file.getFileName())
            .body(resource);
}}
"""),
    ("spring", "c", "java", "public ResponseEntity<Resource> download", 0, """@GetMapping("/reports/{{name}}")
public ResponseEntity<Resource> download(@PathVariable String name) throws IOException {{
    Path base = Paths.get(reportsDir).toRealPath();
    Path file = base.resolve(name).normalize();
    if (!file.startsWith(base)) {{
        return ResponseEntity.badRequest().build();
    }}
    Resource resource = new UrlResource(file.toUri());
    return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=" + file.getFileName())
            .body(resource);
}}
"""),
]

# ---------------------------------------------------------------------------------------------
# API7 — SSRF en servicios de integración
# ---------------------------------------------------------------------------------------------
PRODUCCION["ssrf"] = [
    ("spring", "c", "java", "public WebhookCheckResult verify", 1, """@Service
@RequiredArgsConstructor
public class WebhookVerificationService {{

    private final WebClient webClient;

    public WebhookCheckResult verify(WebhookRegistration registration) {{
        String response = webClient.get()
                .uri(registration.getCallbackUrl())
                .retrieve()
                .bodyToMono(String.class)
                .block(Duration.ofSeconds(5));
        return new WebhookCheckResult(registration.getId(), response != null);
    }}
}}
"""),
    ("spring", "c", "java", "public WebhookCheckResult verify", 0, """@Service
@RequiredArgsConstructor
public class WebhookVerificationService {{

    private final WebClient webClient;
    private final AllowedHostsPolicy allowedHosts;

    public WebhookCheckResult verify(WebhookRegistration registration) {{
        URI uri = URI.create(registration.getCallbackUrl());
        if (!"https".equals(uri.getScheme()) || !allowedHosts.contains(uri.getHost())) {{
            throw new InvalidWebhookException("host not allowed");
        }}
        String response = webClient.get().uri(uri).retrieve().bodyToMono(String.class).block(Duration.ofSeconds(5));
        return new WebhookCheckResult(registration.getId(), response != null);
    }}
}}
"""),
    ("drf", "c", "py", "def post(self, request", 1, """class ImportCatalogView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        feed_url = request.data.get("feed_url")
        resp = requests.get(feed_url, timeout=10)
        items = resp.json().get("items", [])
        created = CatalogImporter(request.user).run(items)
        return Response({{"created": created}}, status=201)
"""),
    ("drf", "c", "py", "def post(self, request", 0, """class ImportCatalogView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        feed_url = request.data.get("feed_url", "")
        if urlparse(feed_url).hostname not in settings.ALLOWED_FEED_HOSTS:
            return Response({{"error": "feed host not allowed"}}, status=400)
        resp = requests.get(feed_url, timeout=10, allow_redirects=False)
        items = resp.json().get("items", [])
        created = CatalogImporter(request.user).run(items)
        return Response({{"created": created}}, status=201)
"""),
    ("nest", "c", "ts", "async fetchPreview(", 1, """@Injectable()
export class LinkPreviewService {{
  constructor(private readonly http: HttpService) {{}}

  async fetchPreview(dto: PreviewRequestDto): Promise<PreviewDto> {{
    const {{ data }} = await firstValueFrom(this.http.get(dto.url, {{ timeout: 4000 }}));
    return PreviewDto.fromHtml(data);
  }}
}}
"""),
    ("nest", "c", "ts", "async fetchPreview(", 0, """@Injectable()
export class LinkPreviewService {{
  constructor(private readonly http: HttpService) {{}}

  async fetchPreview(dto: PreviewRequestDto): Promise<PreviewDto> {{
    const target = new URL(dto.url);
    if (target.protocol !== 'https:' || !ALLOWED_PREVIEW_HOSTS.includes(target.hostname)) {{
      throw new BadRequestException('host not allowed');
    }}
    const {{ data }} = await firstValueFrom(this.http.get(target.toString(), {{ timeout: 4000, maxRedirects: 0 }}));
    return PreviewDto.fromHtml(data);
  }}
}}
"""),
]

# ---------------------------------------------------------------------------------------------
# API2 — tokens: verificación débil y secretos en el código
# ---------------------------------------------------------------------------------------------
PRODUCCION["jwt_inseguro"] = [
    ("spring", "c", "java", "protected void doFilterInternal", 1, """@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {{

    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {{
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {{
            JWTClaimsSet claims = JWTParser.parse(header.substring(7)).getJWTClaimsSet();
            UserDetails user = userDetailsService.loadUserByUsername(claims.getSubject());
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()));
        }}
        chain.doFilter(request, response);
    }}
}}
"""),
    ("spring", "c", "java", "protected void doFilterInternal", 0, """@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {{

    private final UserDetailsService userDetailsService;
    private final JwtDecoder jwtDecoder;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {{
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {{
            Jwt jwt = jwtDecoder.decode(header.substring(7));
            UserDetails user = userDetailsService.loadUserByUsername(jwt.getSubject());
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()));
        }}
        chain.doFilter(request, response);
    }}
}}
"""),
    ("nest", "c", "ts", "constructor(private readonly users: UsersService)", 1, """@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {{
  constructor(private readonly users: UsersService) {{
    super({{
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: true,
      secretOrKey: 'super-secret-{ent}-key',
    }});
  }}

  async validate(payload: JwtPayload) {{
    return this.users.findById(payload.sub);
  }}
}}
"""),
    ("nest", "c", "ts", "constructor(private readonly users: UsersService, config: ConfigService)", 0, """@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {{
  constructor(private readonly users: UsersService, config: ConfigService) {{
    super({{
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.getOrThrow<string>('JWT_SECRET'),
    }});
  }}

  async validate(payload: JwtPayload) {{
    return this.users.findById(payload.sub);
  }}
}}
"""),
]

PRODUCCION["secreto_codigo"] = [
    ("fastapi", "c", "py", "def create_access_token(", 1, """SECRET_KEY = "dev-{ent}-secret-key-2024"
ALGORITHM = "HS256"


def create_access_token(subject: str, expires_minutes: int = 60) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    payload = {{"sub": subject, "exp": expire, "scope": "user"}}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
"""),
    ("fastapi", "c", "py", "def create_access_token(", 0, """SECRET_KEY = settings.JWT_SECRET_KEY
ALGORITHM = "HS256"


def create_access_token(subject: str, expires_minutes: int = 60) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    payload = {{"sub": subject, "exp": expire, "scope": "user"}}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
"""),
]

# ---------------------------------------------------------------------------------------------
# A08 — deserialización insegura en integraciones
# ---------------------------------------------------------------------------------------------
PRODUCCION["deserializacion"] = [
    ("fastapi", "c", "py", "async def restore_session(", 1, """@router.post("/sessions/restore")
async def restore_session(request: Request, user=Depends(get_current_user)):
    blob = base64.b64decode(request.cookies.get("cart_state", ""))
    state = pickle.loads(blob)
    await cart_service.restore(user.id, state)
    return {{"restored": True}}
"""),
    ("fastapi", "c", "py", "async def restore_session(", 0, """@router.post("/sessions/restore")
async def restore_session(request: Request, user=Depends(get_current_user)):
    raw = base64.b64decode(request.cookies.get("cart_state", ""))
    state = CartState.model_validate_json(raw)
    await cart_service.restore(user.id, state)
    return {{"restored": True}}
"""),
    ("spring", "c", "java", "public ImportResult importSnapshot", 1, """@PostMapping(value = "/snapshots/import", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
public ImportResult importSnapshot(InputStream body) throws IOException, ClassNotFoundException {{
    try (ObjectInputStream in = new ObjectInputStream(body)) {{
        Snapshot snapshot = (Snapshot) in.readObject();
        return snapshotService.apply(snapshot);
    }}
}}
"""),
    ("spring", "c", "java", "public ImportResult importSnapshot", 0, """@PostMapping(value = "/snapshots/import", consumes = MediaType.APPLICATION_JSON_VALUE)
public ImportResult importSnapshot(@Valid @RequestBody SnapshotDto body) {{
    Snapshot snapshot = snapshotMapper.fromDto(body);
    return snapshotService.apply(snapshot);
}}
"""),
    ("express", "c", "js", "router.post('/settings/import'", 1, """router.post('/settings/import', authenticate, upload.single('file'), async (req, res) => {{
  const settings = yaml.load(req.file.buffer.toString('utf8'), {{ schema: yaml.DEFAULT_FULL_SCHEMA }});
  await settingsService.apply(req.user.id, settings);
  res.status(204).end();
}});
"""),
    ("express", "c", "js", "router.post('/settings/import'", 0, """router.post('/settings/import', authenticate, upload.single('file'), async (req, res) => {{
  const raw = yaml.load(req.file.buffer.toString('utf8'), {{ schema: yaml.FAILSAFE_SCHEMA }});
  const settings = settingsSchema.parse(raw);
  await settingsService.apply(req.user.id, settings);
  res.status(204).end();
}});
"""),
]

# ---------------------------------------------------------------------------------------------
# API8 / A10 — errores con detalle interno en manejadores globales
# ---------------------------------------------------------------------------------------------
PRODUCCION["error_expuesto"] = [
    ("express", "c", "js", "function errorHandler(err, req, res, next)", 1, """function errorHandler(err, req, res, next) {{
  const statusCode = err.statusCode || 500;
  logger.error(err);
  res.status(statusCode).json({{
    code: statusCode,
    message: err.message,
    stack: err.stack,
    query: req.query,
  }});
}}

module.exports = {{ errorHandler }};
"""),
    ("express", "c", "js", "function errorHandler(err, req, res, next)", 0, """function errorHandler(err, req, res, next) {{
  const statusCode = err.statusCode || 500;
  logger.error(err);
  res.status(statusCode).json({{
    code: statusCode,
    message: statusCode < 500 ? err.publicMessage : 'Internal server error',
    requestId: req.id,
  }});
}}

module.exports = {{ errorHandler }};
"""),
    ("drf", "c", "py", "def custom_exception_handler(", 1, """def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is None:
        logger.exception("unhandled error")
        return Response({{"error": str(exc), "trace": traceback.format_exc()}}, status=500)
    return response
"""),
    ("drf", "c", "py", "def custom_exception_handler(", 0, """def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is None:
        logger.exception("unhandled error")
        return Response({{"error": "internal error"}}, status=500)
    return response
"""),
]

# Especificación de las familias que no existen en el generador base
FAMILIAS_NUEVAS = {
    "sqli": dict(cwe=["CWE-89"], api=[], owasp=["A05:2025"]),
    "cmdi": dict(cwe=["CWE-78"], api=[], owasp=["A05:2025"]),
    "path_traversal": dict(cwe=["CWE-22"], api=[], owasp=["A01:2025"]),
    "deserializacion": dict(cwe=["CWE-502"], api=[], owasp=["A08:2025"]),
    "secreto_codigo": dict(cwe=["CWE-798"], api=["API2:2023"], owasp=["A07:2025"]),
}
NOMBRES_ARCHIVO_PRODUCCION = {"drf": "views.py"}

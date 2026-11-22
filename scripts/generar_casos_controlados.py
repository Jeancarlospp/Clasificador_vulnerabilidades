"""Genera los casos controlados de vulnerabilidades de API y configuración (fase SAMPLE).

Las fuentes públicas casi no contienen ejemplos etiquetados de autorización a nivel de objeto
(API1), de función (API5), de asignación masiva (API3), de consumo de recursos (API4), de
inventario (API9) ni de consumo inseguro de APIs (API10). Para cubrirlos se escribieron
plantillas de *pares* vulnerable / corregido en cinco frameworks de microservicios
(Express, NestJS, FastAPI, Flask y Spring Boot) y en archivos de configuración.

Para que el modelo no memorice las plantillas:
- cada plantilla se instancia con distintas entidades, nombres de campos y de variables;
- existen al menos dos estilos de escritura por familia y framework;
- la partición del dataset agrupa por (familia, framework, estilo), de modo que la prueba
  contiene estilos que el modelo no vio durante el entrenamiento.

Salida: datos/casos_controlados/<familia>/<archivo> y datos/casos_controlados/manifiesto.json

Uso: python scripts/generar_casos_controlados.py
"""

import json
import random
import shutil
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SALIDA = BASE / "datos" / "casos_controlados"
random.seed(2026)

ENTIDADES = [
    ("order", "orders", "Order"), ("invoice", "invoices", "Invoice"), ("document", "documents", "Document"),
    ("ticket", "tickets", "Ticket"), ("payment", "payments", "Payment"), ("address", "addresses", "Address"),
    ("message", "messages", "Message"), ("report", "reports", "Report"), ("vehicle", "vehicles", "Vehicle"),
    ("booking", "bookings", "Booking"), ("shipment", "shipments", "Shipment"), ("note", "notes", "Note"),
    ("account", "accounts", "Account"), ("card", "cards", "Card"), ("appointment", "appointments", "Appointment"),
    ("project", "projects", "Project"), ("contract", "contracts", "Contract"), ("receipt", "receipts", "Receipt"),
]
DUENO = ["userId", "ownerId", "customerId", "accountId", "createdBy"]
DUENO_PY = ["user_id", "owner_id", "customer_id", "account_id", "created_by"]


def camel(s):
    return s[0].upper() + s[1:]


def contexto():
    ent, ents, Ent = random.choice(ENTIDADES)
    k = random.randrange(len(DUENO))
    return {"ent": ent, "ents": ents, "Ent": Ent, "own": DUENO[k], "own_py": DUENO_PY[k],
            "Own": camel(DUENO[k]), "svc": random.choice(["service", "svc", f"{ent}Service"]),
            "repo": random.choice([f"{ent}Repository", f"{ent}Repo", "repository"]),
            "idv": random.choice(["id", f"{ent}Id", "itemId"]), "idv_py": random.choice(["id", f"{ent}_id", "item_id"]),
            "lim": random.choice([20, 25, 50, 100]), "n": random.randint(2, 9)}


# Cada familia: lista de plantillas (framework, estilo, extensión, ancla, vulnerable, texto)
# El ancla identifica la línea del handler etiquetado. {..} se rellena con contexto().
F = {}

# ---------------------------------------------------------------------------------------------
# API1 — BOLA (CWE-639)
# ---------------------------------------------------------------------------------------------
F["bola"] = dict(cwe=["CWE-639"], api=["API1:2023"], owasp=["A01:2025"], plantillas=[
    ("express", "a", "js", "router.get('/{ents}/:{idv}'", 1, """const express = require('express');
const router = express.Router();
const {Ent} = require('../models/{ent}');
const auth = require('../middleware/auth');

router.get('/{ents}/:{idv}', auth, async (req, res) => {{
  const {ent} = await {Ent}.findById(req.params.{idv});
  if (!{ent}) return res.status(404).json({{ message: 'Not found' }});
  res.json({ent});
}});

module.exports = router;
"""),
    ("express", "a", "js", "router.get('/{ents}/:{idv}'", 0, """const express = require('express');
const router = express.Router();
const {Ent} = require('../models/{ent}');
const auth = require('../middleware/auth');

router.get('/{ents}/:{idv}', auth, async (req, res) => {{
  const {ent} = await {Ent}.findOne({{ _id: req.params.{idv}, {own}: req.user.id }});
  if (!{ent}) return res.status(404).json({{ message: 'Not found' }});
  res.json({ent});
}});

module.exports = router;
"""),
    ("express", "b", "js", "router.delete(", 1, """const router = require('express').Router();
const db = require('../db');

router.delete('/api/{ents}/:{idv}', verifyToken, function (req, res, next) {{
  db.{ents}.destroy({{ where: {{ id: req.params.{idv} }} }})
    .then(() => res.status(204).end())
    .catch(next);
}});

module.exports = router;
"""),
    ("express", "b", "js", "router.delete(", 0, """const router = require('express').Router();
const db = require('../db');

router.delete('/api/{ents}/:{idv}', verifyToken, function (req, res, next) {{
  db.{ents}.findByPk(req.params.{idv})
    .then(({ent}) => {{
      if (!{ent} || {ent}.{own} !== req.user.id) return res.status(403).json({{ error: 'Forbidden' }});
      return {ent}.destroy().then(() => res.status(204).end());
    }})
    .catch(next);
}});

module.exports = router;
"""),
    ("nest", "a", "ts", "@Get(':{idv}')", 1, """import {{ Controller, Get, Param, UseGuards }} from '@nestjs/common';
import {{ JwtAuthGuard }} from '../auth/jwt-auth.guard';
import {{ {Ent}Service }} from './{ent}.service';

@Controller('{ents}')
@UseGuards(JwtAuthGuard)
export class {Ent}Controller {{
  constructor(private readonly {svc}: {Ent}Service) {{}}

  @Get(':{idv}')
  async findOne(@Param('{idv}') {idv}: string) {{
    return this.{svc}.findById({idv});
  }}
}}
"""),
    ("nest", "a", "ts", "@Get(':{idv}')", 0, """import {{ Controller, Get, Param, UseGuards, ForbiddenException, Req }} from '@nestjs/common';
import {{ JwtAuthGuard }} from '../auth/jwt-auth.guard';
import {{ {Ent}Service }} from './{ent}.service';

@Controller('{ents}')
@UseGuards(JwtAuthGuard)
export class {Ent}Controller {{
  constructor(private readonly {svc}: {Ent}Service) {{}}

  @Get(':{idv}')
  async findOne(@Param('{idv}') {idv}: string, @Req() req) {{
    const {ent} = await this.{svc}.findById({idv});
    if ({ent}.{own} !== req.user.sub) {{
      throw new ForbiddenException();
    }}
    return {ent};
  }}
}}
"""),
    ("nest", "b", "ts", "@Patch(':{idv}')", 1, """import {{ Body, Controller, Param, Patch, UseGuards }} from '@nestjs/common';
import {{ AuthGuard }} from '@nestjs/passport';

@Controller('api/{ents}')
export class {Ent}sController {{
  constructor(private readonly {repo}: {Ent}Repository) {{}}

  @UseGuards(AuthGuard('jwt'))
  @Patch(':{idv}')
  update(@Param('{idv}') {idv}: number, @Body() dto: Update{Ent}Dto) {{
    return this.{repo}.update({{ id: {idv} }}, dto);
  }}
}}
"""),
    ("nest", "b", "ts", "@Patch(':{idv}')", 0, """import {{ Body, Controller, Param, Patch, UseGuards }} from '@nestjs/common';
import {{ AuthGuard }} from '@nestjs/passport';
import {{ CurrentUser }} from '../auth/current-user.decorator';

@Controller('api/{ents}')
export class {Ent}sController {{
  constructor(private readonly {repo}: {Ent}Repository) {{}}

  @UseGuards(AuthGuard('jwt'))
  @Patch(':{idv}')
  update(@Param('{idv}') {idv}: number, @Body() dto: Update{Ent}Dto, @CurrentUser() user: User) {{
    return this.{repo}.update({{ id: {idv}, {own}: user.id }}, dto);
  }}
}}
"""),
    ("fastapi", "a", "py", "@router.get(", 1, """from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.auth import get_current_user
from app.models import {Ent}

router = APIRouter(prefix="/{ents}")


@router.get("/{{{idv_py}}}")
def read_{ent}({idv_py}: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    {ent} = db.query({Ent}).filter({Ent}.id == {idv_py}).first()
    if {ent} is None:
        raise HTTPException(status_code=404, detail="{Ent} not found")
    return {ent}
"""),
    ("fastapi", "a", "py", "@router.get(", 0, """from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.auth import get_current_user
from app.models import {Ent}

router = APIRouter(prefix="/{ents}")


@router.get("/{{{idv_py}}}")
def read_{ent}({idv_py}: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    {ent} = db.query({Ent}).filter({Ent}.id == {idv_py}, {Ent}.{own_py} == user.id).first()
    if {ent} is None:
        raise HTTPException(status_code=404, detail="{Ent} not found")
    return {ent}
"""),
    ("fastapi", "b", "py", "@app.put(", 1, """from fastapi import FastAPI, Depends
from .security import current_user
from . import crud, schemas

app = FastAPI()


@app.put("/api/v1/{ents}/{{{idv_py}}}")
async def update_{ent}({idv_py}: str, payload: schemas.{Ent}Update, user: dict = Depends(current_user)):
    {ent} = await crud.get_{ent}({idv_py})
    await crud.update_{ent}({ent}, payload)
    return {{"status": "updated"}}
"""),
    ("fastapi", "b", "py", "@app.put(", 0, """from fastapi import FastAPI, Depends, HTTPException, status
from .security import current_user
from . import crud, schemas

app = FastAPI()


@app.put("/api/v1/{ents}/{{{idv_py}}}")
async def update_{ent}({idv_py}: str, payload: schemas.{Ent}Update, user: dict = Depends(current_user)):
    {ent} = await crud.get_{ent}({idv_py})
    if {ent} is None or {ent}.{own_py} != user["id"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    await crud.update_{ent}({ent}, payload)
    return {{"status": "updated"}}
"""),
    ("flask", "a", "py", "@bp.route(", 1, """from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from .models import {Ent}

bp = Blueprint("{ents}", __name__)


@bp.route("/{ents}/<int:{idv_py}>", methods=["GET"])
@jwt_required()
def get_{ent}({idv_py}):
    {ent} = {Ent}.query.get_or_404({idv_py})
    return jsonify({ent}.to_dict())
"""),
    ("flask", "a", "py", "@bp.route(", 0, """from flask import Blueprint, jsonify, abort
from flask_jwt_extended import jwt_required, get_jwt_identity
from .models import {Ent}

bp = Blueprint("{ents}", __name__)


@bp.route("/{ents}/<int:{idv_py}>", methods=["GET"])
@jwt_required()
def get_{ent}({idv_py}):
    {ent} = {Ent}.query.get_or_404({idv_py})
    if {ent}.{own_py} != get_jwt_identity():
        abort(403)
    return jsonify({ent}.to_dict())
"""),
    ("spring", "a", "java", "@GetMapping(", 1, """package com.example.{ents};

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/{ents}")
public class {Ent}Controller {{

    private final {Ent}Repository {repo};

    public {Ent}Controller({Ent}Repository {repo}) {{
        this.{repo} = {repo};
    }}

    @GetMapping("/{{{idv}}}")
    public ResponseEntity<{Ent}> get{Ent}(@PathVariable Long {idv}) {{
        return {repo}.findById({idv})
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }}
}}
"""),
    ("spring", "a", "java", "@GetMapping(", 0, """package com.example.{ents};

import java.security.Principal;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/{ents}")
public class {Ent}Controller {{

    private final {Ent}Repository {repo};

    public {Ent}Controller({Ent}Repository {repo}) {{
        this.{repo} = {repo};
    }}

    @GetMapping("/{{{idv}}}")
    public ResponseEntity<{Ent}> get{Ent}(@PathVariable Long {idv}, Principal principal) {{
        return {repo}.findByIdAndOwnerUsername({idv}, principal.getName())
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }}
}}
"""),
    ("spring", "b", "java", "@DeleteMapping(", 1, """package com.example.api;

import org.springframework.web.bind.annotation.*;

@RestController
public class {Ent}Resource {{

    @Autowired
    private {Ent}Service {svc};

    @DeleteMapping("/{ents}/{{{idv}}}")
    public void delete{Ent}(@PathVariable("{idv}") String {idv}) {{
        {svc}.deleteById({idv});
    }}
}}
"""),
    ("spring", "b", "java", "@DeleteMapping(", 0, """package com.example.api;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
public class {Ent}Resource {{

    @Autowired
    private {Ent}Service {svc};

    @DeleteMapping("/{ents}/{{{idv}}}")
    public void delete{Ent}(@PathVariable("{idv}") String {idv}, @AuthenticationPrincipal UserDetails user) {{
        {Ent} {ent} = {svc}.findById({idv});
        if (!{ent}.getOwner().equals(user.getUsername())) {{
            throw new AccessDeniedException("Not owner");
        }}
        {svc}.deleteById({idv});
    }}
}}
"""),
])

# ---------------------------------------------------------------------------------------------
# API5 — BFLA (CWE-862)
# ---------------------------------------------------------------------------------------------
F["bfla"] = dict(cwe=["CWE-862"], api=["API5:2023"], owasp=["A01:2025"], plantillas=[
    ("express", "a", "js", "router.delete('/admin", 1, """const router = require('express').Router();
const User = require('../models/user');
const {{ authenticate }} = require('../middleware/auth');

router.delete('/admin/users/:id', authenticate, async (req, res) => {{
  await User.deleteOne({{ _id: req.params.id }});
  res.status(204).send();
}});

module.exports = router;
"""),
    ("express", "a", "js", "router.delete('/admin", 0, """const router = require('express').Router();
const User = require('../models/user');
const {{ authenticate, requireRole }} = require('../middleware/auth');

router.delete('/admin/users/:id', authenticate, requireRole('admin'), async (req, res) => {{
  await User.deleteOne({{ _id: req.params.id }});
  res.status(204).send();
}});

module.exports = router;
"""),
    ("express", "b", "js", "app.put('/api/users/:id/role'", 1, """module.exports = function (app, db) {{
  app.put('/api/users/:id/role', isAuthenticated, async function (req, res) {{
    const user = await db.users.findByPk(req.params.id);
    user.role = req.body.role;
    await user.save();
    res.json({{ ok: true }});
  }});
}};
"""),
    ("express", "b", "js", "app.put('/api/users/:id/role'", 0, """module.exports = function (app, db) {{
  app.put('/api/users/:id/role', isAuthenticated, async function (req, res) {{
    if (req.user.role !== 'admin') {{
      return res.status(403).json({{ error: 'Admins only' }});
    }}
    const user = await db.users.findByPk(req.params.id);
    user.role = req.body.role;
    await user.save();
    res.json({{ ok: true }});
  }});
}};
"""),
    ("nest", "a", "ts", "@Delete(':id')", 1, """import {{ Controller, Delete, Get, Param, UseGuards }} from '@nestjs/common';
import {{ JwtAuthGuard }} from '../auth/jwt.guard';

@Controller('admin/users')
@UseGuards(JwtAuthGuard)
export class AdminUsersController {{
  constructor(private readonly users: UsersService) {{}}

  @Delete(':id')
  remove(@Param('id') id: string) {{
    return this.users.remove(id);
  }}
}}
"""),
    ("nest", "a", "ts", "@Delete(':id')", 0, """import {{ Controller, Delete, Get, Param, UseGuards }} from '@nestjs/common';
import {{ JwtAuthGuard }} from '../auth/jwt.guard';
import {{ RolesGuard }} from '../auth/roles.guard';
import {{ Roles }} from '../auth/roles.decorator';

@Controller('admin/users')
@UseGuards(JwtAuthGuard, RolesGuard)
export class AdminUsersController {{
  constructor(private readonly users: UsersService) {{}}

  @Roles('admin')
  @Delete(':id')
  remove(@Param('id') id: string) {{
    return this.users.remove(id);
  }}
}}
"""),
    ("nest", "b", "ts", "@Get('all')", 1, """@Controller('users')
export class UsersController {{
  constructor(private readonly usersService: UsersService) {{}}

  @UseGuards(AuthGuard('jwt'))
  @Get('all')
  async listAll(): Promise<User[]> {{
    return this.usersService.findAll();
  }}
}}
"""),
    ("nest", "b", "ts", "@Get('all')", 0, """@Controller('users')
export class UsersController {{
  constructor(private readonly usersService: UsersService) {{}}

  @UseGuards(AuthGuard('jwt'), RolesGuard)
  @Roles(Role.Admin)
  @Get('all')
  async listAll(): Promise<User[]> {{
    return this.usersService.findAll({{ take: {lim} }});
  }}
}}
"""),
    ("fastapi", "a", "py", "@router.post(", 1, """from fastapi import APIRouter, Depends
from app.deps import get_current_user

router = APIRouter(prefix="/admin")


@router.post("/{ents}/{{{idv_py}}}/approve")
def approve_{ent}({idv_py}: int, user=Depends(get_current_user)):
    {ent} = {Ent}.get({idv_py})
    {ent}.status = "approved"
    {ent}.save()
    return {{"approved": {idv_py}}}
"""),
    ("fastapi", "a", "py", "@router.post(", 0, """from fastapi import APIRouter, Depends
from app.deps import get_current_admin

router = APIRouter(prefix="/admin")


@router.post("/{ents}/{{{idv_py}}}/approve")
def approve_{ent}({idv_py}: int, admin=Depends(get_current_admin)):
    {ent} = {Ent}.get({idv_py})
    {ent}.status = "approved"
    {ent}.save()
    return {{"approved": {idv_py}}}
"""),
    ("flask", "a", "py", "@app.route(", 1, """from flask import Flask, jsonify
from flask_login import login_required
from models import User

app = Flask(__name__)


@app.route("/api/admin/users", methods=["GET"])
@login_required
def list_users():
    users = User.query.all()
    return jsonify([u.serialize() for u in users])
"""),
    ("flask", "a", "py", "@app.route(", 0, """from flask import Flask, jsonify, abort
from flask_login import login_required, current_user
from models import User

app = Flask(__name__)


@app.route("/api/admin/users", methods=["GET"])
@login_required
def list_users():
    if not current_user.is_admin:
        abort(403)
    users = User.query.limit({lim}).all()
    return jsonify([u.serialize() for u in users])
"""),
    ("spring", "a", "java", "@PostMapping(", 1, """@RestController
@RequestMapping("/api/admin")
public class AdminController {{

    private final UserService userService;

    public AdminController(UserService userService) {{
        this.userService = userService;
    }}

    @PostMapping("/users/{{id}}/promote")
    public ResponseEntity<Void> promote(@PathVariable Long id) {{
        userService.grantRole(id, "ADMIN");
        return ResponseEntity.ok().build();
    }}
}}
"""),
    ("spring", "a", "java", "@PostMapping(", 0, """@RestController
@RequestMapping("/api/admin")
public class AdminController {{

    private final UserService userService;

    public AdminController(UserService userService) {{
        this.userService = userService;
    }}

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/users/{{id}}/promote")
    public ResponseEntity<Void> promote(@PathVariable Long id) {{
        userService.grantRole(id, "ADMIN");
        return ResponseEntity.ok().build();
    }}
}}
"""),
])

# ---------------------------------------------------------------------------------------------
# API3 — asignación masiva (CWE-915) y exposición de propiedades (CWE-213)
# ---------------------------------------------------------------------------------------------
F["asignacion_masiva"] = dict(cwe=["CWE-915"], api=["API3:2023"], owasp=["A08:2025"], plantillas=[
    ("express", "a", "js", "router.put('/profile'", 1, """router.put('/profile', auth, async (req, res) => {{
  const user = await User.findById(req.user.id);
  Object.assign(user, req.body);
  await user.save();
  res.json({{ message: 'Profile updated' }});
}});
"""),
    ("express", "a", "js", "router.put('/profile'", 0, """router.put('/profile', auth, async (req, res) => {{
  const user = await User.findById(req.user.id);
  const {{ name, email, phone }} = req.body;
  Object.assign(user, {{ name, email, phone }});
  await user.save();
  res.json({{ message: 'Profile updated' }});
}});
"""),
    ("express", "b", "js", "router.post('/register'", 1, """router.post('/register', async (req, res) => {{
  const user = await User.create(req.body);
  res.status(201).json({{ id: user.id }});
}});
"""),
    ("express", "b", "js", "router.post('/register'", 0, """router.post('/register', async (req, res) => {{
  const {{ username, email, password }} = req.body;
  const hash = await bcrypt.hash(password, 12);
  const user = await User.create({{ username, email, password: hash, role: 'user' }});
  res.status(201).json({{ id: user.id }});
}});
"""),
    ("fastapi", "a", "py", "@router.patch(", 1, """@router.patch("/me")
def update_me(data: dict, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    for key, value in data.items():
        setattr(user, key, value)
    db.commit()
    return {{"ok": True}}
"""),
    ("fastapi", "a", "py", "@router.patch(", 0, """class ProfileUpdate(BaseModel):
    full_name: str | None = None
    email: EmailStr | None = None


@router.patch("/me")
def update_me(data: ProfileUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(user, key, value)
    db.commit()
    return {{"ok": True}}
"""),
    ("flask", "a", "py", "@app.route(", 1, """@app.route("/api/users/me", methods=["PUT"])
@jwt_required()
def update_user():
    user = User.query.get(get_jwt_identity())
    user.__dict__.update(request.get_json())
    db.session.commit()
    return jsonify(status="ok")
"""),
    ("flask", "a", "py", "@app.route(", 0, """EDITABLE = {{"name", "bio", "avatar"}}


@app.route("/api/users/me", methods=["PUT"])
@jwt_required()
def update_user():
    user = User.query.get(get_jwt_identity())
    data = request.get_json() or {{}}
    for field in EDITABLE & data.keys():
        setattr(user, field, data[field])
    db.session.commit()
    return jsonify(status="ok")
"""),
    ("spring", "a", "java", "@PutMapping(", 1, """@PutMapping("/me")
public User updateProfile(@RequestBody User changes, Principal principal) {{
    User current = userRepository.findByUsername(principal.getName());
    BeanUtils.copyProperties(changes, current, "id");
    return userRepository.save(current);
}}
"""),
    ("spring", "a", "java", "@PutMapping(", 0, """@PutMapping("/me")
public UserResponse updateProfile(@Valid @RequestBody ProfileUpdateDto changes, Principal principal) {{
    User current = userRepository.findByUsername(principal.getName());
    current.setDisplayName(changes.getDisplayName());
    current.setEmail(changes.getEmail());
    return UserResponse.from(userRepository.save(current));
}}
"""),
    ("nest", "a", "ts", "@Put('me')", 1, """@Put('me')
@UseGuards(JwtAuthGuard)
async updateMe(@Req() req, @Body() body: any) {{
  return this.usersRepository.update(req.user.id, body);
}}
"""),
    ("nest", "a", "ts", "@Put('me')", 0, """@Put('me')
@UseGuards(JwtAuthGuard)
async updateMe(@Req() req, @Body() body: UpdateProfileDto) {{
  const {{ displayName, bio }} = body;
  return this.usersRepository.update(req.user.id, {{ displayName, bio }});
}}
"""),
])

F["exposicion_datos"] = dict(cwe=["CWE-213"], api=["API3:2023"], owasp=["A01:2025"], plantillas=[
    ("express", "a", "js", "router.get('/users/:id'", 1, """router.get('/users/:id', auth, async (req, res) => {{
  const user = await User.findById(req.params.id);
  res.json(user);
}});
"""),
    ("express", "a", "js", "router.get('/users/:id'", 0, """router.get('/users/:id', auth, async (req, res) => {{
  const user = await User.findById(req.params.id).select('username avatar bio');
  res.json(user);
}});
"""),
    ("fastapi", "a", "py", "@router.get(", 1, """@router.get("/users/{{user_id}}")
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    return {{"id": user.id, "email": user.email, "password_hash": user.password_hash, "role": user.role,
            "ssn": user.ssn}}
"""),
    ("fastapi", "a", "py", "@router.get(", 0, """@router.get("/users/{{user_id}}", response_model=UserPublic)
def get_user(user_id: int, db: Session = Depends(get_db)):
    user = db.get(User, user_id)
    return UserPublic(id=user.id, display_name=user.display_name)
"""),
    ("spring", "a", "java", "@GetMapping(", 1, """@GetMapping("/users/{{id}}")
public User getUser(@PathVariable Long id) {{
    return userRepository.findById(id).orElseThrow();
}}
"""),
    ("spring", "a", "java", "@GetMapping(", 0, """@GetMapping("/users/{{id}}")
public UserPublicDto getUser(@PathVariable Long id) {{
    User user = userRepository.findById(id).orElseThrow();
    return new UserPublicDto(user.getId(), user.getDisplayName());
}}
"""),
    ("flask", "a", "py", "@app.get(", 1, """@app.get("/api/users/<username>")
def user_detail(username):
    user = User.query.filter_by(username=username).first_or_404()
    return jsonify(user.__dict__)
"""),
    ("flask", "a", "py", "@app.get(", 0, """@app.get("/api/users/<username>")
def user_detail(username):
    user = User.query.filter_by(username=username).first_or_404()
    return jsonify(username=user.username, joined=user.created_at.isoformat())
"""),
])

# ---------------------------------------------------------------------------------------------
# API4 — consumo ilimitado de recursos (CWE-770)
# ---------------------------------------------------------------------------------------------
F["recursos"] = dict(cwe=["CWE-770"], api=["API4:2023"], owasp=["A06:2025"], plantillas=[
    ("express", "a", "js", "router.get('/{ents}'", 1, """router.get('/{ents}', async (req, res) => {{
  const limit = parseInt(req.query.limit) || 10;
  const items = await {Ent}.find().limit(limit);
  res.json(items);
}});
"""),
    ("express", "a", "js", "router.get('/{ents}'", 0, """router.get('/{ents}', async (req, res) => {{
  const limit = Math.min(parseInt(req.query.limit) || 10, {lim});
  const page = Math.max(parseInt(req.query.page) || 1, 1);
  const items = await {Ent}.find().skip((page - 1) * limit).limit(limit);
  res.json(items);
}});
"""),
    ("express", "b", "js", "router.post('/upload'", 1, """const upload = multer({{ dest: 'uploads/' }});

router.post('/upload', auth, upload.single('file'), (req, res) => {{
  res.json({{ path: req.file.path }});
}});
"""),
    ("express", "b", "js", "router.post('/upload'", 0, """const upload = multer({{ dest: 'uploads/', limits: {{ fileSize: 5 * 1024 * 1024, files: 1 }} }});

router.post('/upload', auth, upload.single('file'), (req, res) => {{
  res.json({{ path: req.file.path }});
}});
"""),
    ("fastapi", "a", "py", "@router.get(", 1, """@router.get("/{ents}")
def list_{ents}(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query({Ent}).offset(skip).limit(limit).all()
"""),
    ("fastapi", "a", "py", "@router.get(", 0, """@router.get("/{ents}")
def list_{ents}(skip: int = Query(0, ge=0), limit: int = Query(20, ge=1, le={lim}), db: Session = Depends(get_db)):
    return db.query({Ent}).offset(skip).limit(limit).all()
"""),
    ("flask", "a", "py", "@app.route(", 1, """@app.route("/api/{ents}/export")
def export_{ents}():
    rows = {Ent}.query.all()
    return jsonify([r.to_dict() for r in rows])
"""),
    ("flask", "a", "py", "@app.route(", 0, """@app.route("/api/{ents}/export")
@limiter.limit("5 per minute")
def export_{ents}():
    page = request.args.get("page", 1, type=int)
    rows = {Ent}.query.paginate(page=page, per_page={lim}, max_per_page={lim})
    return jsonify([r.to_dict() for r in rows.items])
"""),
    ("spring", "a", "java", "@GetMapping", 1, """@GetMapping("/{ents}")
public List<{Ent}> list(@RequestParam(defaultValue = "1000000") int size) {{
    return {repo}.findAll(PageRequest.of(0, size)).getContent();
}}
"""),
    ("spring", "a", "java", "@GetMapping", 0, """@GetMapping("/{ents}")
public List<{Ent}> list(@RequestParam(defaultValue = "20") @Max({lim}) int size) {{
    return {repo}.findAll(PageRequest.of(0, Math.min(size, {lim}))).getContent();
}}
"""),
    ("nest", "a", "ts", "@Get()", 1, """@Get()
findAll(@Query('take') take: number) {{
  return this.{repo}.find({{ take }});
}}
"""),
    ("nest", "a", "ts", "@Get()", 0, """@Get()
@Throttle({{ default: {{ limit: 30, ttl: 60000 }} }})
findAll(@Query('take', new DefaultValuePipe(20), ParseIntPipe) take: number) {{
  return this.{repo}.find({{ take: Math.min(take, {lim}) }});
}}
"""),
])

# ---------------------------------------------------------------------------------------------
# API2 — autenticación: login sin límite de intentos (CWE-307) y JWT sin verificar (CWE-347)
# ---------------------------------------------------------------------------------------------
F["login_sin_limite"] = dict(cwe=["CWE-307"], api=["API2:2023"], owasp=["A07:2025"], plantillas=[
    ("express", "a", "js", "router.post('/login'", 1, """router.post('/login', async (req, res) => {{
  const user = await User.findOne({{ email: req.body.email }});
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {{
    return res.status(401).json({{ error: 'Invalid credentials' }});
  }}
  res.json({{ token: signToken(user) }});
}});
"""),
    ("express", "a", "js", "router.post('/login'", 0, """const loginLimiter = rateLimit({{ windowMs: 15 * 60 * 1000, max: 5 }});

router.post('/login', loginLimiter, async (req, res) => {{
  const user = await User.findOne({{ email: req.body.email }});
  if (!user || !(await bcrypt.compare(req.body.password, user.password))) {{
    return res.status(401).json({{ error: 'Invalid credentials' }});
  }}
  res.json({{ token: signToken(user) }});
}});
"""),
    ("fastapi", "a", "py", "@router.post(", 1, """@router.post("/auth/token")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate(db, form.username, form.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {{"access_token": create_access_token(user.id), "token_type": "bearer"}}
"""),
    ("fastapi", "a", "py", "@router.post(", 0, """@router.post("/auth/token")
@limiter.limit("5/minute")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate(db, form.username, form.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {{"access_token": create_access_token(user.id), "token_type": "bearer"}}
"""),
    ("spring", "a", "java", "@PostMapping", 1, """@PostMapping("/api/auth/otp/verify")
public ResponseEntity<?> verifyOtp(@RequestBody OtpRequest req) {{
    if (otpService.isValid(req.getEmail(), req.getOtp())) {{
        return ResponseEntity.ok(tokenService.issue(req.getEmail()));
    }}
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
}}
"""),
    ("spring", "a", "java", "@PostMapping", 0, """@PostMapping("/api/auth/otp/verify")
public ResponseEntity<?> verifyOtp(@RequestBody OtpRequest req) {{
    if (attemptService.isBlocked(req.getEmail())) {{
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).build();
    }}
    if (otpService.isValid(req.getEmail(), req.getOtp())) {{
        attemptService.reset(req.getEmail());
        return ResponseEntity.ok(tokenService.issue(req.getEmail()));
    }}
    attemptService.registerFailure(req.getEmail());
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
}}
"""),
    ("flask", "a", "py", "@app.route(", 1, """@app.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(username=request.form["username"]).first()
    if user and check_password_hash(user.password, request.form["password"]):
        login_user(user)
        return redirect(url_for("index"))
    return render_template("login.html", error="Invalid"), 401
"""),
    ("flask", "a", "py", "@app.route(", 0, """@app.route("/login", methods=["POST"])
@limiter.limit("10 per hour")
def login():
    user = User.query.filter_by(username=request.form["username"]).first()
    if user and check_password_hash(user.password, request.form["password"]):
        login_user(user)
        return redirect(url_for("index"))
    return render_template("login.html", error="Invalid"), 401
"""),
])

F["jwt_inseguro"] = dict(cwe=["CWE-347"], api=["API2:2023"], owasp=["A04:2025"], plantillas=[
    ("express", "a", "js", "function authenticate", 1, """function authenticate(req, res, next) {{
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const payload = jwt.decode(token);
  if (!payload) return res.status(401).end();
  req.user = payload;
  next();
}}
"""),
    ("express", "a", "js", "function authenticate", 0, """function authenticate(req, res, next) {{
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  try {{
    req.user = jwt.verify(token, process.env.JWT_SECRET, {{ algorithms: ['HS256'] }});
    next();
  }} catch (err) {{
    return res.status(401).end();
  }}
}}
"""),
    ("express", "b", "js", "jwt.verify(", 1, """const verifyToken = (req, res, next) => {{
  const token = req.cookies.token;
  jwt.verify(token, process.env.JWT_SECRET, {{ ignoreExpiration: true }}, (err, decoded) => {{
    if (err) return res.sendStatus(403);
    req.user = decoded;
    next();
  }});
}};
"""),
    ("express", "b", "js", "jwt.verify(", 0, """const verifyToken = (req, res, next) => {{
  const token = req.cookies.token;
  jwt.verify(token, process.env.JWT_SECRET, {{ algorithms: ['HS256'], maxAge: '1h' }}, (err, decoded) => {{
    if (err) return res.sendStatus(403);
    req.user = decoded;
    next();
  }});
}};
"""),
    ("fastapi", "a", "py", "def get_current_user", 1, """def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = jwt.decode(token, options={{"verify_signature": False}})
    user = users.get(payload["sub"])
    if user is None:
        raise HTTPException(status_code=401)
    return user
"""),
    ("fastapi", "a", "py", "def get_current_user", 0, """def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401)
    user = users.get(payload["sub"])
    if user is None:
        raise HTTPException(status_code=401)
    return user
"""),
    ("spring", "a", "java", "public Claims parse", 1, """public Claims parse(String token) {{
    int i = token.lastIndexOf('.');
    String withoutSignature = token.substring(0, i + 1);
    return Jwts.parser().parseClaimsJwt(withoutSignature).getBody();
}}
"""),
    ("spring", "a", "java", "public Claims parse", 0, """public Claims parse(String token) {{
    return Jwts.parserBuilder()
            .setSigningKey(signingKey)
            .build()
            .parseClaimsJws(token)
            .getBody();
}}
"""),
])

# ---------------------------------------------------------------------------------------------
# API7 — SSRF (CWE-918) y API10 — consumo inseguro de APIs
# ---------------------------------------------------------------------------------------------
F["ssrf"] = dict(cwe=["CWE-918"], api=["API7:2023"], owasp=["A01:2025"], plantillas=[
    ("express", "a", "js", "router.post('/preview'", 1, """router.post('/preview', auth, async (req, res) => {{
  const response = await axios.get(req.body.url);
  res.send(response.data);
}});
"""),
    ("express", "a", "js", "router.post('/preview'", 0, """const ALLOWED_HOSTS = new Set(['images.example.com', 'cdn.example.com']);

router.post('/preview', auth, async (req, res) => {{
  const target = new URL(req.body.url);
  if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) {{
    return res.status(400).json({{ error: 'URL not allowed' }});
  }}
  const response = await axios.get(target.toString(), {{ timeout: 3000, maxRedirects: 0 }});
  res.send(response.data);
}});
"""),
    ("fastapi", "a", "py", "@router.post(", 1, """@router.post("/{ents}/{{{idv_py}}}/import")
def import_{ent}({idv_py}: int, body: ImportRequest):
    r = requests.get(body.source_url)
    return {{"size": len(r.content)}}
"""),
    ("fastapi", "a", "py", "@router.post(", 0, """ALLOWED_DOMAINS = {{"api.partner.com", "files.partner.com"}}


@router.post("/{ents}/{{{idv_py}}}/import")
def import_{ent}({idv_py}: int, body: ImportRequest):
    host = urlparse(body.source_url).hostname
    if host not in ALLOWED_DOMAINS:
        raise HTTPException(status_code=400, detail="domain not allowed")
    r = requests.get(body.source_url, timeout=5, allow_redirects=False)
    return {{"size": len(r.content)}}
"""),
    ("spring", "a", "java", "@PostMapping", 1, """@PostMapping("/webhooks/test")
public String testWebhook(@RequestParam String callbackUrl) {{
    return restTemplate.getForObject(callbackUrl, String.class);
}}
"""),
    ("spring", "a", "java", "@PostMapping", 0, """@PostMapping("/webhooks/test")
public String testWebhook(@RequestParam String callbackUrl) {{
    URI uri = URI.create(callbackUrl);
    if (!"https".equals(uri.getScheme()) || !allowedHosts.contains(uri.getHost())) {{
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "host not allowed");
    }}
    return restTemplate.getForObject(uri, String.class);
}}
"""),
    ("flask", "a", "py", "@app.route(", 1, """@app.route("/fetch-avatar")
def fetch_avatar():
    url = request.args.get("avatar_url")
    data = urllib.request.urlopen(url).read()
    return Response(data, mimetype="image/png")
"""),
    ("flask", "a", "py", "@app.route(", 0, """@app.route("/fetch-avatar")
def fetch_avatar():
    url = request.args.get("avatar_url", "")
    if urlparse(url).hostname not in ALLOWED_AVATAR_HOSTS:
        abort(400)
    data = requests.get(url, timeout=3, allow_redirects=False).content
    return Response(data, mimetype="image/png")
"""),
])

F["consumo_inseguro"] = dict(cwe=["CWE-295"], api=["API10:2023"], owasp=["A07:2025"], plantillas=[
    ("fastapi", "a", "py", "async def sync_rates", 1, """async def sync_rates(db: Session):
    resp = requests.get("https://rates.partner.io/v1/latest", verify=False)
    for item in resp.json()["rates"]:
        db.execute(text(f"UPDATE rates SET value = {{item['value']}} WHERE code = '{{item['code']}}'"))
    db.commit()
"""),
    ("fastapi", "a", "py", "async def sync_rates", 0, """async def sync_rates(db: Session):
    resp = requests.get("https://rates.partner.io/v1/latest", timeout=10)
    resp.raise_for_status()
    payload = RatesResponse.model_validate(resp.json())
    for item in payload.rates:
        db.execute(text("UPDATE rates SET value = :v WHERE code = :c"), {{"v": item.value, "c": item.code}})
    db.commit()
"""),
    ("express", "a", "js", "async function fetchShipping", 1, """async function fetchShipping(orderId) {{
  const agent = new https.Agent({{ rejectUnauthorized: false }});
  const {{ data }} = await axios.get(`https://shipping.partner.net/track/${{orderId}}`, {{ httpsAgent: agent }});
  await db.query(`UPDATE orders SET status = '${{data.status}}' WHERE id = ${{orderId}}`);
  return data;
}}
"""),
    ("express", "a", "js", "async function fetchShipping", 0, """async function fetchShipping(orderId) {{
  const {{ data }} = await axios.get(`https://shipping.partner.net/track/${{encodeURIComponent(orderId)}}`, {{ timeout: 5000 }});
  const status = trackingSchema.parse(data).status;
  await db.query('UPDATE orders SET status = $1 WHERE id = $2', [status, orderId]);
  return {{ status }};
}}
"""),
    ("spring", "a", "java", "public void syncCatalog", 1, """public void syncCatalog() {{
    String body = restTemplate.getForObject("http://catalog.partner.com/api/products", String.class);
    List<Product> products = mapper.readValue(body, new TypeReference<List<Product>>() {{}});
    productRepository.saveAll(products);
}}
"""),
    ("spring", "a", "java", "public void syncCatalog", 0, """public void syncCatalog() {{
    ProductPage page = webClient.get().uri("https://catalog.partner.com/api/products")
            .retrieve().bodyToMono(ProductPage.class).timeout(Duration.ofSeconds(5)).block();
    List<Product> products = page.items().stream().filter(validator::isValid).map(Product::from).toList();
    productRepository.saveAll(products);
}}
"""),
    ("flask", "a", "py", "def import_partner_users", 1, """def import_partner_users():
    r = requests.get("http://partner-crm.local/api/users", verify=False)
    for u in r.json():
        db.session.add(User(**u))
    db.session.commit()
"""),
    ("flask", "a", "py", "def import_partner_users", 0, """def import_partner_users():
    r = requests.get("https://partner-crm.example.com/api/users", timeout=10)
    r.raise_for_status()
    for u in PartnerUserSchema(many=True).load(r.json()):
        db.session.add(User(username=u["username"], email=u["email"]))
    db.session.commit()
"""),
])

# ---------------------------------------------------------------------------------------------
# API8 / A10 — errores expuestos (CWE-209) y fallo abierto (CWE-636); A09 — registro (CWE-532)
# ---------------------------------------------------------------------------------------------
F["error_expuesto"] = dict(cwe=["CWE-209"], api=["API8:2023"], owasp=["A10:2025"], plantillas=[
    ("express", "a", "js", "router.get('/{ents}/:id'", 1, """router.get('/{ents}/:id', async (req, res) => {{
  try {{
    const row = await repo.find{Ent}(req.params.id);
    res.json(row);
  }} catch (err) {{
    res.status(500).json({{ error: err.message, stack: err.stack }});
  }}
}});
"""),
    ("express", "a", "js", "router.get('/{ents}/:id'", 0, """router.get('/{ents}/:id', async (req, res) => {{
  try {{
    const row = await repo.find{Ent}(req.params.id);
    res.json(row);
  }} catch (err) {{
    logger.error('failed to load {ent}', {{ id: req.params.id, err }});
    res.status(500).json({{ error: 'Internal server error' }});
  }}
}});
"""),
    ("fastapi", "a", "py", "@router.post(", 1, """@router.post("/{ents}")
def create_{ent}(payload: {Ent}In, db: Session = Depends(get_db)):
    try:
        return crud.create(db, payload)
    except Exception as e:
        return JSONResponse(status_code=500, content={{"detail": str(e), "trace": traceback.format_exc()}})
"""),
    ("fastapi", "a", "py", "@router.post(", 0, """@router.post("/{ents}")
def create_{ent}(payload: {Ent}In, db: Session = Depends(get_db)):
    try:
        return crud.create(db, payload)
    except IntegrityError:
        logger.exception("integrity error creating {ent}")
        raise HTTPException(status_code=409, detail="Conflict")
"""),
    ("spring", "a", "java", "@ExceptionHandler", 1, """@ExceptionHandler(Exception.class)
public ResponseEntity<Map<String, Object>> handle(Exception ex) {{
    Map<String, Object> body = new HashMap<>();
    body.put("error", ex.getMessage());
    body.put("trace", Arrays.toString(ex.getStackTrace()));
    return ResponseEntity.status(500).body(body);
}}
"""),
    ("spring", "a", "java", "@ExceptionHandler", 0, """@ExceptionHandler(Exception.class)
public ResponseEntity<Map<String, Object>> handle(Exception ex) {{
    log.error("Unhandled error", ex);
    return ResponseEntity.status(500).body(Map.of("error", "Internal error"));
}}
"""),
])

F["fallo_abierto"] = dict(cwe=["CWE-636"], api=[], owasp=["A10:2025"], plantillas=[
    ("express", "a", "js", "async function checkPermission", 1, """async function checkPermission(req, res, next) {{
  try {{
    const allowed = await policyClient.isAllowed(req.user.id, req.path);
    if (!allowed) return res.status(403).end();
    next();
  }} catch (err) {{
    next();
  }}
}}
"""),
    ("express", "a", "js", "async function checkPermission", 0, """async function checkPermission(req, res, next) {{
  try {{
    const allowed = await policyClient.isAllowed(req.user.id, req.path);
    if (!allowed) return res.status(403).end();
    next();
  }} catch (err) {{
    logger.error('policy service unavailable', err);
    return res.status(503).end();
  }}
}}
"""),
    ("fastapi", "a", "py", "def is_authorized", 1, """def is_authorized(user_id: int, resource: str) -> bool:
    try:
        return policy_service.check(user_id, resource)
    except Exception:
        return True
"""),
    ("fastapi", "a", "py", "def is_authorized", 0, """def is_authorized(user_id: int, resource: str) -> bool:
    try:
        return policy_service.check(user_id, resource)
    except PolicyServiceError:
        logger.warning("policy check failed for %s", resource)
        return False
"""),
    ("spring", "a", "java", "public boolean hasAccess", 1, """public boolean hasAccess(String user, String resource) {{
    try {{
        return aclClient.check(user, resource);
    }} catch (Exception e) {{
        return true;
    }}
}}
"""),
    ("spring", "a", "java", "public boolean hasAccess", 0, """public boolean hasAccess(String user, String resource) {{
    try {{
        return aclClient.check(user, resource);
    }} catch (AclException e) {{
        log.warn("ACL check failed", e);
        return false;
    }}
}}
"""),
])

F["log_sensible"] = dict(cwe=["CWE-532"], api=[], owasp=["A09:2025"], plantillas=[
    ("express", "a", "js", "router.post('/auth/login'", 1, """router.post('/auth/login', async (req, res) => {{
  logger.info(`login attempt user=${{req.body.username}} password=${{req.body.password}}`);
  const token = await authService.login(req.body.username, req.body.password);
  res.json({{ token }});
}});
"""),
    ("express", "a", "js", "router.post('/auth/login'", 0, """router.post('/auth/login', async (req, res) => {{
  logger.info('login attempt', {{ username: req.body.username, ip: req.ip }});
  const token = await authService.login(req.body.username, req.body.password);
  res.json({{ token }});
}});
"""),
    ("fastapi", "a", "py", "def create_payment", 1, """def create_payment(card: CardIn, user=Depends(get_current_user)):
    logger.info("payment for %s card=%s cvv=%s", user.email, card.number, card.cvv)
    return gateway.charge(card, amount=card.amount)
"""),
    ("fastapi", "a", "py", "def create_payment", 0, """def create_payment(card: CardIn, user=Depends(get_current_user)):
    logger.info("payment for user_id=%s card=****%s", user.id, card.number[-4:])
    return gateway.charge(card, amount=card.amount)
"""),
    ("spring", "a", "java", "public TokenResponse login", 1, """public TokenResponse login(LoginRequest req) {{
    log.debug("Login request for {{}} with password {{}}", req.getUsername(), req.getPassword());
    String token = jwtService.issue(authenticate(req));
    log.info("Issued token {{}}", token);
    return new TokenResponse(token);
}}
"""),
    ("spring", "a", "java", "public TokenResponse login", 0, """public TokenResponse login(LoginRequest req) {{
    log.debug("Login request for {{}}", req.getUsername());
    String token = jwtService.issue(authenticate(req));
    log.info("Issued token for {{}}", req.getUsername());
    return new TokenResponse(token);
}}
"""),
])

# ---------------------------------------------------------------------------------------------
# Configuración: Spring Boot (A02/API8, A07/API2, API9), OpenAPI (API9), manifiestos (A03),
# docker-compose (A07/API2 secretos)
# ---------------------------------------------------------------------------------------------
F["spring_config"] = dict(cwe=["CWE-16"], api=["API8:2023"], owasp=["A02:2025"], plantillas=[
    ("properties", "a", "properties", "management.endpoints.web.exposure.include", 1, """spring.application.name={ent}-service
server.port=808{n}
management.endpoints.web.exposure.include=*
management.endpoint.health.show-details=always
"""),
    ("properties", "a", "properties", "management.endpoints.web.exposure.include", 0, """spring.application.name={ent}-service
server.port=808{n}
management.endpoints.web.exposure.include=health,info
management.endpoint.health.show-details=never
"""),
    ("properties", "b", "properties", "server.error.include-stacktrace", 1, """server.port=80{n}0
server.error.include-stacktrace=always
server.error.include-message=always
logging.level.root=DEBUG
spring.jpa.show-sql=true
"""),
    ("properties", "b", "properties", "server.error.include-stacktrace", 0, """server.port=80{n}0
server.error.include-stacktrace=never
server.error.include-message=never
logging.level.root=INFO
spring.jpa.show-sql=false
"""),
    ("yaml", "a", "yml", "  h2:", 1, """spring:
  application:
    name: {ent}-service
  h2:
    console:
      enabled: true
      settings:
        web-allow-others: true
  datasource:
    url: jdbc:h2:mem:{ents}
"""),
    ("yaml", "a", "yml", "  h2:", 0, """spring:
  application:
    name: {ent}-service
  h2:
    console:
      enabled: false
  datasource:
    url: ${{DATABASE_URL}}
"""),
])

F["secreto_config"] = dict(cwe=["CWE-798"], api=["API2:2023"], owasp=["A07:2025"], plantillas=[
    ("properties", "a", "properties", "spring.datasource.password", 1, """spring.datasource.url=jdbc:postgresql://db:5432/{ents}
spring.datasource.username={ent}_app
spring.datasource.password=Pa55w0rd{n}{n}
jwt.secret=my-{ent}-jwt-secret-key-{n}
"""),
    ("properties", "a", "properties", "spring.datasource.password", 0, """spring.datasource.url=${{DB_URL}}
spring.datasource.username=${{DB_USER}}
spring.datasource.password=${{DB_PASSWORD}}
jwt.secret=${{JWT_SECRET}}
"""),
    ("compose", "a", "yml", "    environment:", 1, """services:
  {ent}-service:
    build: ./{ent}-service
    environment:
      - DB_PASSWORD=supersecret{n}
      - JWT_SECRET=changeme{n}{n}
      - STRIPE_API_KEY=sk_live_{n}{n}{n}abcXYZ
    ports:
      - "808{n}:8080"
"""),
    ("compose", "a", "yml", "    environment:", 0, """services:
  {ent}-service:
    build: ./{ent}-service
    environment:
      - DB_PASSWORD=${{DB_PASSWORD}}
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
    secrets:
      - jwt_secret
    ports:
      - "808{n}:8080"
"""),
    ("yaml", "a", "yml", "  datasource:", 1, """spring:
  datasource:
    url: jdbc:mysql://mysql:3306/{ents}
    username: root
    password: root{n}{n}{n}
"""),
    ("yaml", "a", "yml", "  datasource:", 0, """spring:
  datasource:
    url: ${{SPRING_DATASOURCE_URL}}
    username: ${{SPRING_DATASOURCE_USERNAME}}
    password: ${{SPRING_DATASOURCE_PASSWORD}}
"""),
])

F["inventario"] = dict(cwe=["CWE-1059"], api=["API9:2023"], owasp=["A02:2025"], plantillas=[
    ("openapi", "a", "yaml", "servers:", 1, """openapi: 3.0.3
info:
  title: {Ent} API
  version: 2.{n}.0
servers:
  - url: https://api.example.com/v2
  - url: http://staging-api.example.com/v1
  - url: http://dev.example.internal:808{n}
paths:
  /v2/{ents}:
    get:
      summary: List {ents}
"""),
    ("openapi", "a", "yaml", "servers:", 0, """openapi: 3.0.3
info:
  title: {Ent} API
  version: 2.{n}.0
servers:
  - url: https://api.example.com/v2
paths:
  /v2/{ents}:
    get:
      summary: List {ents}
"""),
    ("openapi", "b", "yaml", "  /v1/", 1, """openapi: 3.0.3
info:
  title: {Ent} API
  version: 3.0.0
paths:
  /v1/{ents}/{{id}}:
    get:
      deprecated: true
      summary: Legacy {ent} lookup (no auth)
      security: []
"""),
    ("openapi", "b", "yaml", "  /v3/", 0, """openapi: 3.0.3
info:
  title: {Ent} API
  version: 3.0.0
paths:
  /v3/{ents}/{{id}}:
    get:
      summary: Get {ent}
      security:
        - bearerAuth: []
"""),
    ("properties", "a", "properties", "springdoc.swagger-ui.enabled", 1, """# perfil de produccion
spring.profiles.active=prod
springdoc.api-docs.enabled=true
springdoc.swagger-ui.enabled=true
springdoc.swagger-ui.path=/docs
"""),
    ("properties", "a", "properties", "springdoc.swagger-ui.enabled", 0, """# perfil de produccion
spring.profiles.active=prod
springdoc.api-docs.enabled=false
springdoc.swagger-ui.enabled=false
"""),
])

F["dependencias"] = dict(cwe=["CWE-1104"], api=[], owasp=["A03:2025"], plantillas=[
    ("package", "a", "json", "\"dependencies\"", 1, """{{
  "name": "{ent}-service",
  "version": "1.{n}.0",
  "dependencies": {{
    "express": "*",
    "jsonwebtoken": "latest",
    "lodash": ">=4.0.0",
    "mongoose": "^5"
  }}
}}
"""),
    ("package", "a", "json", "\"dependencies\"", 0, """{{
  "name": "{ent}-service",
  "version": "1.{n}.0",
  "dependencies": {{
    "express": "4.21.2",
    "jsonwebtoken": "9.0.2",
    "lodash": "4.17.21",
    "mongoose": "8.9.5"
  }}
}}
"""),
    ("requirements", "a", "txt", "fastapi", 1, """fastapi
uvicorn
requests>=2.0
pyyaml
sqlalchemy
"""),
    ("requirements", "a", "txt", "fastapi", 0, """fastapi==0.115.6
uvicorn==0.34.0
requests==2.32.3
pyyaml==6.0.2
sqlalchemy==2.0.36
"""),
    ("pom", "a", "xml", "<dependency>", 1, """<project>
  <artifactId>{ent}-service</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>LATEST</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>[2.0,)</version>
    </dependency>
  </dependencies>
</project>
"""),
    ("pom", "a", "xml", "<dependency>", 0, """<project>
  <artifactId>{ent}-service</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.24.3</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>2.18.2</version>
    </dependency>
  </dependencies>
</project>
"""),
])

F["cors_codigo"] = dict(cwe=["CWE-942"], api=["API8:2023"], owasp=["A02:2025"], plantillas=[
    ("express", "a", "js", "app.use(cors(", 1, """const app = express();
app.use(express.json());
app.use(cors({{ origin: true, credentials: true }}));
app.use('/api/{ents}', {ent}Router);
"""),
    ("express", "a", "js", "app.use(cors(", 0, """const app = express();
app.use(express.json());
app.use(cors({{ origin: ['https://app.example.com'], credentials: true }}));
app.use('/api/{ents}', {ent}Router);
"""),
    ("fastapi", "a", "py", "app.add_middleware(", 1, """app = FastAPI(title="{Ent} service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
)
app.include_router({ent}_router)
"""),
    ("fastapi", "a", "py", "app.add_middleware(", 0, """app = FastAPI(title="{Ent} service")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
)
app.include_router({ent}_router)
"""),
    ("spring", "a", "java", "public void addCorsMappings", 1, """@Configuration
public class WebConfig implements WebMvcConfigurer {{
    @Override
    public void addCorsMappings(CorsRegistry registry) {{
        registry.addMapping("/**").allowedOriginPatterns("*").allowCredentials(true);
    }}
}}
"""),
    ("spring", "a", "java", "public void addCorsMappings", 0, """@Configuration
public class WebConfig implements WebMvcConfigurer {{
    @Override
    public void addCorsMappings(CorsRegistry registry) {{
        registry.addMapping("/api/**").allowedOrigins("https://app.example.com").allowCredentials(true);
    }}
}}
"""),
])

COMENTARIOS = ["Endpoint del servicio de {ents}", "Ver ticket SEC-{n}{n}{n}", "Generado a partir del contrato v{n}",
               "Mantener sincronizado con el gateway", "Revisado en la iteracion {n}", "Modulo de {ent}s",
               "Handler principal", "Configuracion del entorno {n}", "Equipo de plataforma", "Ultima revision: sprint {n}"]
MENSAJES = {"'Not found'": ["'Not found'", "'Resource not found'", "'not_found'", "'No encontrado'"],
            "'Forbidden'": ["'Forbidden'", "'forbidden'", "'Access denied'", "'Not allowed'"],
            "'Invalid credentials'": ["'Invalid credentials'", "'Bad credentials'", "'Login failed'"],
            "\"Not found\"": ["\"Not found\"", "\"not found\"", "\"Recurso no encontrado\""],
            "'Internal server error'": ["'Internal server error'", "'Unexpected error'", "'Something went wrong'"]}
# variables locales que se renombran de forma coherente en cada instancia
LOCALES = {"user": ["user", "member", "account", "principalUser", "u"], "items": ["items", "results", "rows", "records"],
           "row": ["row", "record", "entry"], "err": ["err", "error", "ex"], "payload": ["payload", "claims", "decoded"],
           "body": ["body", "reqBody", "input"], "changes": ["changes", "incoming", "patch"], "rows": ["rows", "list", "found"],
           "current": ["current", "existing", "entity"], "resp": ["resp", "response", "res2"]}
SINTAXIS_COMENTARIO = {"js": "// ", "ts": "// ", "java": "// ", "py": "# ", "properties": "# ", "yml": "# ", "yaml": "# ",
                       "txt": "# ", "xml": None, "json": None}


def variar(texto, ext, ctx):
    """Variación superficial que no cambia la semántica de seguridad del caso."""
    for original, opciones in MENSAJES.items():
        if original in texto:
            texto = texto.replace(original, random.choice(opciones))
    if ext in ("js", "ts", "py", "java"):
        import re
        for local, opciones in LOCALES.items():
            nuevo = random.choice(opciones)
            texto = re.sub(r"(?<![.\w'\"])" + local + r"(?![\w'\"])", nuevo, texto)
        prefijo = random.choice(["", "/api", "/api/v1", "/v2"])
        if prefijo and "('/api" not in texto:
            texto = texto.replace("('/", f"('{prefijo}/")
            ctx["_prefijo"] = prefijo
    if ext == "txt":
        lineas = texto.strip().splitlines()
        random.shuffle(lineas)
        extra = random.choice(["httpx", "pydantic", "redis", "celery", "alembic"])
        lineas.append(extra if "==" not in lineas[0] else f"{extra}==1.{ctx['n']}.0")
        texto = "\n".join(lineas) + "\n"
    marca = SINTAXIS_COMENTARIO.get(ext)
    if marca:
        texto = marca + random.choice(COMENTARIOS).format(**ctx) + "\n" + texto
    elif ext == "xml":
        texto = "<!-- " + random.choice(COMENTARIOS).format(**ctx) + " -->\n" + texto
    return texto


NOMBRES_ARCHIVO = {"express": "routes.js", "nest": "controller.ts", "fastapi": "router.py", "flask": "views.py",
                   "spring": "Controller.java", "properties": "application.properties", "yaml": "application.yml",
                   "compose": "docker-compose.yml", "openapi": "openapi.yaml", "package": "package.json",
                   "requirements": "requirements.txt", "pom": "pom.xml"}


def main(instancias=12):
    if SALIDA.exists():
        shutil.rmtree(SALIDA)
    manifiesto = []
    for familia, spec in F.items():
        for k, (fw, estilo, ext, ancla, vulnerable, plantilla) in enumerate(spec["plantillas"]):
            for i in range(instancias):
                ctx = contexto()
                texto = variar(plantilla.format(**ctx), ext, ctx)
                ancla_txt = ancla.format(**ctx)
                if ctx.get("_prefijo"):
                    ancla_txt = ancla_txt.replace("('/", f"('{ctx['_prefijo']}/")
                linea = next((n + 1 for n, l in enumerate(texto.splitlines()) if ancla_txt in l), None)
                if linea is None:
                    raise ValueError(f"ancla no encontrada: {familia} {fw} {ancla_txt}")
                base = NOMBRES_ARCHIVO[fw]
                if fw == "spring":
                    base = f"{ctx['Ent']}{base}"
                carpeta = f"{familia}/{fw}_{estilo}_{k:02d}_{i}"
                ruta = SALIDA / carpeta / base
                ruta.parent.mkdir(parents=True, exist_ok=True)
                ruta.write_text(texto, encoding="utf-8")
                manifiesto.append({
                    "archivo": f"{carpeta}/{base}", "linea": linea, "vulnerable": vulnerable,
                    "cwe": spec["cwe"] if vulnerable else [], "api2023": spec["api"] if vulnerable else [],
                    "owasp2025": spec["owasp"] if vulnerable else [],
                    "familia": familia, "framework": fw, "estilo": estilo,
                    "grupo": f"{familia}|{fw}|{estilo}",
                })
    (SALIDA / "manifiesto.json").write_text(json.dumps(manifiesto, indent=1, ensure_ascii=False))
    vul = sum(m["vulnerable"] for m in manifiesto)
    print(f"Casos controlados: {len(manifiesto)} ({vul} vulnerables, {len(manifiesto) - vul} corregidos) "
          f"en {len(F)} familias")


if __name__ == "__main__":
    main()

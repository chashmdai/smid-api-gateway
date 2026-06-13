# API Gateway — Ecosistema SMID (Defensoría de la Niñez)

Frontera única de entrada del ecosistema **SMID**. Valida el contrato de claims
**2.4** (firma HS256 por `kid`, `iss`, `aud`, `exp` con tolerancia de reloj),
normaliza **todo** error al sobre unificado **2.5**, audita el tráfico con un
identificador de correlación y enruta hacia el Núcleo Fundacional y los
servicios legados del patrón *strangler*. Corre en el puerto `8080`.

> **Rewrite total** del Gateway legado, conforme a la *Auditoría y Plan de
> Refactorización* (`auditoria-refactor-gateway.md`) y al contrato del Núcleo
> Fundacional. Cierra las ocho brechas P0/P1 (B1–B8) sin alterar el modelo de
> rutas ni el formato del sobre que ya emite `smid-auth`.

---

## 1. Responsabilidad del servicio

El Gateway **valida y enruta**; no firma tokens ni guarda estado. La emisión y
renovación de credenciales es responsabilidad exclusiva de `smid-auth`. Aquí se
concentra la **seguridad perimetral**: verificación de la firma y los claims de
cada token, CORS, y la traducción de cualquier fallo al sobre del ecosistema.

```
                          ┌──────────────────────────────────────────┐
                          │            API GATEWAY :8080             │
  React  ───────────────► │  CORS · valida JWT (kid/iss/aud/exp) ·    │
  (Authorization: Bearer) │  audita X-Request-Id · normaliza errores  │
                          └───────────────┬──────────────────────────┘
                                          │ (Authorization pass-through, intacto)
        ┌─────────────────┬───────────────┼───────────────┬─────────────────┐
        ▼                 ▼               ▼               ▼                 ▼
   auth :8081      catalogo :8087   personas :8088  requerim. :8089   legados :808x
```

La clave secreta HS256 es **compartida** con `smid-auth` y debe coincidir **byte
a byte**. El Gateway no reescribe la credencial ni inyecta cabeceras sintéticas
de identidad: cada microservicio vuelve a validar el token (defensa en
profundidad).

---

## 2. Stack

| Componente   | Versión / Detalle                                         |
|--------------|-----------------------------------------------------------|
| Java         | 21                                                        |
| Spring Boot  | 3.5.15                                                     |
| Spring Cloud | 2025.0.2 (`spring-cloud-starter-gateway-server-webflux`)  |
| Seguridad    | Spring Security + OAuth2 Resource Server (reactivo)       |
| JWT          | Nimbus JOSE+JWT — verificación HS256 con selección por `kid` |
| Runtime web  | WebFlux / Netty (no servlet)                              |
| Build        | Maven                                                     |
| Pruebas      | JUnit 5, Reactor Test (`StepVerifier`), `WebTestClient`   |

Sin Lombok: el código nuevo usa **records de Java 21** y constructores
explícitos.

---

## 3. Arquitectura hexagonal (Ports & Adapters)

La regla de dependencia apunta **siempre hacia el dominio**. El núcleo
(`dominio`) no conoce Spring, Jackson ni Netty; el framework vive en los bordes
y se ensambla en `config`.

```
cl.smid.apigateway
├── api                        ← adaptadores de ENTRADA / contrato de salida
│   └── error/
│       ├── ErrorResponse              record del sobre 2.5 (JSON congelado)
│       ├── EscritorRespuestaError     único punto que serializa el sobre
│       └── ManejadorGlobalExcepciones ErrorWebExceptionHandler @Order(-1)
│
├── dominio                    ← NÚCLEO puro (sin framework)
│   └── error/
│       └── CodigoError                catálogo AUTZ-xxx / GTW-xxx (enum)
│
├── infraestructura            ← adaptadores de SALIDA
│   ├── seguridad/
│   │   └── DecodificadorJwtPorKid     fábrica del ReactiveJwtDecoder (kid)
│   └── auditoria/
│       └── FiltroAuditoria            GlobalFilter: X-Request-Id, START/END
│
└── config                     ← composition root
    ├── SeguridadConfig                cadena de filtros, CORS, decoder, 401/403
    ├── PropiedadesJwt                 @ConfigurationProperties smid.jwt.*
    └── PropiedadesCors                @ConfigurationProperties smid.cors.*
```

**Por qué importa:** `DecodificadorJwtPorKid` es una clase de utilidad pura. Se
prueba de forma aislada (ver `DecodificadorJwtPorKidTest`) forjando tokens con
Nimbus, sin levantar contexto de Spring. `SeguridadConfig` es el único lugar que
cablea beans.

---

## 4. Rutas

Todas las rutas externas cuelgan de `/api`. El Núcleo Fundacional usa
`StripPrefix=1` (se recorta solo `/api`; el destino conserva su prefijo, igual
que `smid-auth`). Los legados conservan su `StripPrefix` histórico durante el
*strangler* (decisión D7); solo se externalizaron sus URIs.

| Ruta externa            | Destino (variable)          | Puerto | StripPrefix | Ruta interna resultante      |
|-------------------------|-----------------------------|--------|-------------|------------------------------|
| `/api/auth/**`          | `AUTH_SERVICE_URL`          | 8081   | 1           | `/auth/**`                   |
| `/api/catalogo/**`      | `CATALOGO_SERVICE_URL`      | 8087   | 1           | `/catalogo/**`               |
| `/api/personas/**`      | `PERSONAS_SERVICE_URL`      | 8088   | 1           | `/personas/**`               |
| `/api/requerimientos/**`| `REQUERIMIENTOS_SERVICE_URL`| 8089   | 1           | `/requerimientos/**`         |
| `/api/siger/**`         | `SIGER_SERVICE_URL`         | 8082   | 2           | `/**` (legado)               |
| `/api/sgs/**`           | `SGS_SERVICE_URL`           | 8083   | **0**       | `/api/sgs/**` (legado) ⚠️     |
| `/api/proninez/**`      | `PRONINEZ_SERVICE_URL`      | 8084   | 2           | `/**` (legado)               |
| `/api/smid/**`          | `SMID_SERVICE_URL`          | 8085   | 2           | `/**` (legado)               |
| `/api/esnna/**`         | `ESNNA_SERVICE_URL`         | 8086   | **0**       | `/api/esnna/**` (legado)     |

> ⚠️ **`sgs` con `StripPrefix=0`** preserva el **comportamiento real** del YAML
> legado (el README antiguo decía `2`). La discrepancia quedó documentada en la
> auditoría §3: corregirla es una decisión funcional que exige prueba E2E contra
> el servicio SGS, no una edición silenciosa en este rewrite.

Una petición a una ruta no mapeada produce `404 GTW-404`.

---

## 5. Contrato del token JWT (Núcleo 2.4)

El Gateway acepta tokens **HS256** cuya cabecera declare un `kid` conocido.

**Cabecera**
```json
{ "alg": "HS256", "typ": "JWT", "kid": "smid-2026-06" }
```

**Payload**
```json
{
  "sub": "8f3b...-uuid",      // alt_key del usuario (no el RUT ni el id interno)
  "iss": "smid-auth",
  "aud": "smid-servicios",
  "jti": "<uuid>",
  "roles": ["ADMIN_NACIONAL"],
  "idSede": "uuid-sede",       // alt_key de la sede (opaco)
  "idUnidad": "uuid-unidad",   // alt_key de la unidad (opaco)
  "alcance": "NACIONAL",       // UNIDAD | SEDE | NACIONAL
  "nombre": "Admin SMID",
  "iat": 0,
  "exp": 0
}
```

**Validaciones aplicadas** (cualquier fallo → `401 AUTZ-003`):

- **Firma HS256** verificada con la clave cuyo `kid` coincide con el de la
  cabecera. Se **fuerza** HS256 en el selector (cierre de *algorithm confusion*:
  un token con otro `alg` no encuentra clave).
- **`kid` obligatorio y conocido** (decisión D3, corte duro): un token sin `kid`
  o con un `kid` no mapeado se rechaza de forma determinista, antes de verificar
  la firma. Los tokens del legado —que no portan `kid`— quedan fuera por diseño.
- **`iss` == `smid-auth`** y **`aud` contiene `smid-servicios`**.
- **`exp` / `nbf`** con **skew de reloj de 30 s**. La validación temporal ocurre
  en un solo lugar (`JwtTimestampValidator`), anulando el verificador interno de
  Nimbus (cuyo skew por defecto es 60 s) para no tener dos políticas en
  conflicto.

---

## 6. Manejo de errores (sobre unificado 2.5)

Toda respuesta de error —venga de seguridad o del enrutamiento— usa el **mismo**
sobre. El frontend conmuta sobre `codigo` (estable), nunca sobre `mensaje`.

```json
{
  "status": 401,
  "error": "Unauthorized",
  "codigo": "AUTZ-003",
  "mensaje": "No autenticado. Debe presentar un token de acceso válido.",
  "ruta": "/api/personas/8f3b...",
  "timestamp": "2026-06-12T19:25:46.737771Z"
}
```

- Campos **`ruta`** (no `path`) y **`mensaje`** (no `message`): el contrato está
  **congelado** al formato vigente de `smid-auth` (decisión D2). `timestamp` es
  un `Instant` UTC serializado en ISO-8601.
- **`detalles`** (mapa `campo → mensaje`) es opcional y **se omite** cuando es
  nulo. El Gateway no produce errores de validación de DTO, pero el sobre los
  transporta para coherencia del ecosistema.

### Catálogo de códigos (decisión D1)

| Código     | HTTP | Cuándo                                                                 |
|------------|------|------------------------------------------------------------------------|
| `AUTZ-003` | 401  | Sin token, token inválido/vencido, `kid` desconocido, `iss`/`aud` ajenos |
| `AUTZ-004` | 403  | Autenticado pero sin permisos (reservado a futura RBAC por alcance)    |
| `GTW-001`  | 503  | Destino caído: conexión rechazada o host irresoluble (DNS)             |
| `GTW-002`  | 504  | Destino no respondió dentro del `response-timeout`                     |
| `GTW-404`  | 404  | Ruta no registrada en el Gateway                                       |
| `GTW-500`  | 500  | Falla interna no clasificada (el detalle solo va al log)               |

Para estados HTTP sin entrada canónica (p. ej. 405, 415), el Gateway **sintetiza**
un código estable `GTW-<estado>` (`GTW-405`, `GTW-415`), de modo que el frontend
siempre tenga un `codigo` sobre el cual conmutar.

---

## 7. CORS (brecha B5)

Gobernado por **un solo bean** (`corsConfigurationSource` en `SeguridadConfig`);
no se declara en el YAML de rutas, evitando cabeceras duplicadas. Los orígenes
permitidos vienen por entorno (`CORS_ALLOWED_ORIGINS`, lista separada por comas).

- Métodos: `GET, POST, PUT, PATCH, DELETE, OPTIONS`.
- Cabeceras aceptadas: `Authorization, Content-Type, Accept`.
- Cabecera **expuesta**: `X-Request-Id` (para que el frontend lea el id de
  correlación).
- `allowCredentials = true`, `maxAge = 3600 s`.

---

## 8. Auditoría y trazabilidad

`FiltroAuditoria` (un `GlobalFilter` de orden `-1`) asigna o propaga un
`X-Request-Id` por petición, lo **devuelve** en la cabecera de la respuesta y lo
publica como atributo del intercambio para que el manejador de errores lo
incluya en sus logs. Registra una línea al iniciar (`▶`) y otra al terminar
(`◀`) cada petición que **pasa la seguridad**.

> Nota de diseño: como filtro global, corre **después** de la cadena de
> seguridad. Por tanto, las respuestas `401`/`403` (que la seguridad corta
> antes) no generan línea de auditoría, pero **sí** llevan el sobre unificado.
> Este comportamiento se conserva a propósito (avalado por la auditoría §3).

---

## 9. Configuración por entorno (brecha B3 / DT-2)

`application.yml` contiene **únicamente** referencias `${VARIABLE}`. Ningún
secreto vive en archivos. `JWT_SECRET` **no tiene valor por defecto**: el
Gateway no arranca sin él (fallo rápido y visible). Plantilla completa en
`.env.example`.

| Variable                      | Obligatoria | Por defecto              | Descripción                                   |
|-------------------------------|-------------|--------------------------|-----------------------------------------------|
| `JWT_SECRET`                  | **Sí**      | —                        | Secreto HS256 de la clave vigente (`smid-2026-06`) |
| `JWT_SECRET_ANTERIOR`         | No          | — (comentada)            | Secreto de la clave previa, solo en rotación  |
| `JWT_ISSUER`                  | No          | `smid-auth`              | Emisor esperado (`iss`)                       |
| `JWT_AUDIENCE`                | No          | `smid-servicios`         | Audiencia esperada (`aud`)                    |
| `CORS_ALLOWED_ORIGINS`        | No          | `http://localhost:3000`  | Orígenes permitidos (lista por comas)         |
| `SERVER_PORT`                 | No          | `8080`                   | Puerto del Gateway                            |
| `GATEWAY_CONNECT_TIMEOUT_MS`  | No          | `5000`                   | Timeout de conexión (ms) → habilita `GTW-001` |
| `GATEWAY_RESPONSE_TIMEOUT`    | No          | `30s`                    | Timeout de respuesta → habilita `GTW-002`     |
| `AUTH_SERVICE_URL`            | No          | `http://localhost:8081`  | Destino de Identidad                          |
| `CATALOGO_SERVICE_URL`        | No          | `http://localhost:8087`  | Destino de Catálogo                           |
| `PERSONAS_SERVICE_URL`        | No          | `http://localhost:8088`  | Destino de Personas                           |
| `REQUERIMIENTOS_SERVICE_URL`  | No          | `http://localhost:8089`  | Destino de Requerimientos                     |
| `SIGER_SERVICE_URL`           | No          | `http://localhost:8082`  | Destino legado SIGER                          |
| `SGS_SERVICE_URL`             | No          | `http://localhost:8083`  | Destino legado SGS                            |
| `PRONINEZ_SERVICE_URL`        | No          | `http://localhost:8084`  | Destino legado PRO NIÑEZ                       |
| `SMID_SERVICE_URL`            | No          | `http://localhost:8085`  | Destino legado SMID                           |
| `ESNNA_SERVICE_URL`           | No          | `http://localhost:8086`  | Destino legado ESNNA                          |

### Actuator endurecido (brecha B7)

Solo se exponen `health` e `info` **del propio Gateway**. No hay ruta que alcance
los actuator de los servicios *downstream*.

---

## 10. Runbook — rotación de la clave HS256 (sin caída)

El mapa `kid → secreto` permite rotar sin un corte coordinado:

1. Generar el secreto nuevo: `openssl rand -base64 48`.
2. En `smid-auth`, empezar a firmar con el **nuevo** `kid` (p. ej. `smid-2026-12`).
3. En el Gateway, durante la ventana de transición, cargar **ambas** claves:
   - descomentar la segunda entrada del mapa en `application.yml`
     (`"[smid-2026-06]": ${JWT_SECRET_ANTERIOR}` y la nueva como vigente), y
   - definir `JWT_SECRET` (nueva) y `JWT_SECRET_ANTERIOR` (la que sale).
   Los tokens viejos siguen validando **por su `kid`** hasta expirar.
4. Pasada la vigencia máxima de los tokens viejos, retirar la clave anterior
   (volver a comentar la línea y borrar `JWT_SECRET_ANTERIOR`).

---

## 11. Decisiones de arquitectura resueltas

| ID  | Decisión                                                                                     |
|-----|----------------------------------------------------------------------------------------------|
| D1  | Prefijos de código: `AUTZ-` para auth (consistencia con `smid-auth`), `GTW-` para infraestructura |
| D2  | Sobre 2.5 **congelado** al formato vigente (`ruta`/`mensaje`, no `path`/`message`)           |
| D3  | Rechazo **duro** de tokens sin `kid` o con `kid` desconocido                                  |
| D6  | Núcleo con `StripPrefix=1` estándar (el destino conserva su prefijo, como `smid-auth`)       |
| D7  | Legados conservan su `StripPrefix` real durante el *strangler*; solo se externalizan URIs    |

Brechas cerradas: **B1** (selección por `kid`), **B2** (validación `iss`/`aud`/`exp`),
**B3** (secretos solo por entorno), **B4/B8** (sobre unificado en toda negativa,
incluido token inválido), **B5** (CORS por entorno), **B6** (rutas del Núcleo),
**B7** (actuator endurecido).

---

## 12. Compilar, ejecutar y probar

### Requisitos
- JDK 21
- Maven 3.9+
- Un secreto HS256 (`openssl rand -base64 48`) idéntico al de `smid-auth`.

### Local
```bash
cp .env.example .env
# editar .env: definir al menos JWT_SECRET
# JWT_SECRET, JWT_ISSUER y JWT_AUDIENCE deben coincidir con smid-auth
set -a && source .env && set +a

./mvnw spring-boot:run
```

En Windows/PowerShell:

```powershell
Copy-Item .env.example .env
# editar .env: definir al menos JWT_SECRET
Get-Content .env | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object {
  $name, $value = $_ -split '=', 2
  Set-Item -Path "Env:$name" -Value $value
}

.\mvnw.cmd spring-boot:run
```

En VS Code existe la configuración **Run API Gateway (local)** en
`.vscode/launch.json`. Esta carga `${workspaceFolder}/.env`; el archivo `.env`
es local, está ignorado por Git y no debe contenerse en commits.

Para conversar con `smid-auth` en local:

- `smid-auth` debe estar arriba en `http://localhost:8081`.
- `AUTH_SERVICE_URL` debe apuntar a `http://localhost:8081`.
- El `kid` activo de `smid-auth` debe existir en el mapa `smid.jwt.claves` del
  Gateway. En local, ambos repos usan `smid-2026-06`.
- `JWT_SECRET`, `JWT_ISSUER` y `JWT_AUDIENCE` deben coincidir byte a byte entre
  `smid-auth` y este Gateway.
- Para frontends locales se puede usar
  `CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173`.

### Pruebas
```bash
./mvnw test
```

La suite cubre la matriz E2E §11 en su porción verificable sin servicios reales:

- **`DecodificadorJwtPorKidTest`** (unitaria, sin contexto): token válido,
  rotación por `kid`, `kid` ausente/desconocido, firma forjada, `iss`/`aud`
  ajenos, y la frontera del skew de 30 s.
- **`CodigoErrorTest`**: catálogo canónico y síntesis `GTW-<estado>`.
- **`ApiGatewayApplicationTests`**: carga del contexto completo.
- **`SeguridadIntegracionTest`** (servidor real, puerto aleatorio): `401 AUTZ-003`
  sin token / con token basura / con audiencia ajena; **`503 GTW-001`** con token
  válido hacia un destino caído, incluyendo la cabecera `X-Request-Id`; preflight
  CORS; y `/actuator/health` público.

### Empaquetar
```bash
./mvnw clean package
java -jar target/api-gateway-1.0.0.jar
```

### Verificar salud
```bash
curl -s http://localhost:8080/actuator/health
# {"status":"UP"}
```

### Smoke test con `smid-auth`

Con `smid-auth` y el Gateway levantados:

```powershell
$login = Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8080/api/auth/login `
  -ContentType 'application/json' `
  -Body (@{
    email = 'admin@defensorianinez.cl'
    password = 'Smid.Local.2026'
  } | ConvertTo-Json)

$login.expiraEn
$login.usuario.roles
```

Una llamada protegida con un token válido debe superar la seguridad del Gateway:

```powershell
Invoke-WebRequest `
  -Method Get `
  -Uri http://localhost:8080/api/personas/abc `
  -Headers @{ Authorization = "Bearer $($login.accessToken)" } `
  -SkipHttpErrorCheck
```

Si `personas-service` no está levantado en `localhost:8088`, la respuesta
esperada es `503 GTW-001`: eso confirma que el JWT fue aceptado y que el fallo
ya está en el destino downstream, no en la integración Gateway/Auth.

En producción el Gateway es el único componente expuesto; los microservicios
viven detrás de él. Inyecte la configuración por gestor de secretos / variables
de entorno del orquestador, nunca por archivos versionados.

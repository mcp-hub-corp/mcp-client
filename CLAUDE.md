# MCP-CLIENT: Launcher de Servidores MCP

## 1. Project Goal

**mcp-client** es un ejecutor/launcher de servidores MCP que descarga, valida y ejecuta paquetes MCP desde un registry compatible (por defecto, mcp-registry).

### Qué hace:
- Resuelve referencias inmutables tipo `org/name@version`, `org/name@sha` o `org/name@digest`
- Descarga manifests y bundles validando integridad (SHA-256)
- Ejecuta servidores MCP en modo STDIO o HTTP según el manifest
- Aplica políticas de seguridad ligeras: límites de recursos, aislamiento filesystem, control de red
- Implementa caché local content-addressable para evitar descargas repetidas
- Audita localmente qué se ejecutó (sin exponer datos sensibles)

### Qué NO hace:
- **No es un registry**: solo consume artefactos desde registries compatibles
- **No es un sandbox de VM**: el aislamiento es a nivel de proceso/OS, no virtualización completa
- **No hace análisis dinámico**: no inspecciona comportamiento en tiempo real más allá de aplicar límites
- **No es compatible con npm/pypi/docker**: solo entiende el formato de manifest/bundle de mcp-registry

---

## 2. Key Concepts

### Referencia MCP
Formato: `org/name@version` (semver), `org/name@sha:abc123`, `org/name@digest:sha256:abc...`

### Manifest
Archivo JSON que describe el paquete MCP:
- Metadatos: nombre, versión, autor, licencia
- Entrypoints por plataforma (linux/darwin/windows) y arquitectura (amd64/arm64)
- Transport: STDIO o HTTP
- Requisitos de seguridad: allowlist de red, variables de entorno, subprocess, límites de recursos

### Bundle
Archivo comprimido (tar.gz) con el código ejecutable del servidor MCP. Puede contener:
- Binario nativo
- Scripts (Python, Node.js, etc.) + dependencias

### Digest
Hash SHA-256 inmutable que identifica de forma única un manifest o bundle. La caché local se organiza por digest (content-addressable).

### Resolve
Operación de consulta al registry (`/v1/packages/:org/:name/resolve?ref=...`) que devuelve:
- Digest del manifest
- URL de descarga del manifest
- Digest del bundle
- URL de descarga del bundle

### Cache
Almacenamiento local en `~/.mcp/cache/` organizado por digest:
```
~/.mcp/cache/
  manifests/
    sha256:abc123.../manifest.json
  bundles/
    sha256:def456.../bundle.tar.gz
```

### Entrypoint
Comando a ejecutar dentro del bundle según plataforma y arquitectura:
```json
{
  "entrypoints": {
    "linux-amd64": {
      "command": "./bin/mcp-server",
      "args": ["--mode", "stdio"]
    }
  }
}
```

### Transport
- **STDIO**: servidor lee stdin, escribe stdout (JSON-RPC 2.0)
- **HTTP**: servidor expone API HTTP en puerto configurable

---

## 3. Threat Model (Lightweight)

### Amenazas cubiertas (mitigación razonable):
- **Código malicioso consume recursos ilimitados**: límites de CPU, memoria, pids, fds, timeout
- **Escritura fuera del directorio de trabajo**: filesystem isolation (mejor esfuerzo por OS)
- **Acceso a red no autorizado**: default-deny network (cuando el OS lo permite)
- **Exposición de secretos**: solo se pasan por nombre, nunca loguear valores
- **MITM en descarga**: validación de digest SHA-256 de manifest/bundle
- **Ejecución de paquetes corruptos**: validación manifest→bundle coherence

### Amenazas NO cubiertas (fuera de scope):
- **Ataques a nivel kernel/hardware**: no hay virtualización completa
- **Side-channels**: timing attacks, spectre, etc.
- **Exploits en runtime del bundle**: si el bundle usa un intérprete vulnerable, el launcher no lo detecta
- **Evasión de límites con técnicas avanzadas**: fork bombs muy sofisticadas, etc.
- **Red default-deny en Windows sin drivers**: Windows no tiene eBPF nativo ni netns
- **Seguridad del registry**: si el registry es comprometido y sirve artefactos firmados maliciosamente, el launcher confía en el digest

---

## 4. Security Invariants

Reglas que **NUNCA** se rompen:

1. **No ejecutar sin validar digest**: manifest y bundle deben validar SHA-256 antes de uso
2. **No exponer valores de secretos**: los secretos se pasan por nombre/referencia, nunca plaintext en logs
3. **Default-deny network**: si el manifest no declara allowlist de red, el launcher debe aplicar deny (o documentar limitación del OS)
4. **Filesystem isolation**: el proceso MCP solo debe poder escribir en su directorio de trabajo asignado + tmp dir
5. **Límites de recursos siempre aplicados**: CPU, memoria, pids, fds, timeout en todos los OS
6. **Auditoría obligatoria**: cada ejecución debe registrar qué se ejecutó (package, version, digest, entrypoint, start/end, exit code)
7. **No subprocess por defecto**: si el manifest no declara `subprocess: true`, el launcher debe restringir (o documentar limitación)
8. **No privilegios elevados**: el launcher nunca ejecuta como root/admin

---

## 5. Platform Strategy

### Linux
**Mecanismos disponibles:**
- `rlimits` (RLIMIT_CPU, RLIMIT_AS, RLIMIT_NPROC, RLIMIT_NOFILE)
- `cgroups v2` (cpu.max, memory.max, pids.max) si disponibles
- `unshare` / `clone` con namespaces (net, mount, pid) si viable
- `seccomp` para filtrar syscalls si manifest lo pide

**Estrategia:**
- Por defecto: rlimits + cgroups (si root o cgroups delegado)
- Network default-deny: crear netns vacío o usar eBPF/iptables si manifest no declara allowlist
- Filesystem: bind mount privado del directorio de trabajo + tmpfs para /tmp
- Subprocess: usar seccomp para bloquear fork/exec si manifest no lo permite

**Decisiones:**
- Si no hay cgroups disponibles (usuario sin permisos), aplicar solo rlimits y documentar limitación
- Si no se puede crear netns (CAP_NET_ADMIN), documentar que red no se puede aislar completamente

### macOS
**Mecanismos disponibles:**
- `setrlimit` (RLIMIT_CPU, RLIMIT_AS, RLIMIT_NPROC, RLIMIT_NOFILE)
- Timeouts vía proceso padre

**NO disponibles fácilmente:**
- Network namespaces (no existe en macOS)
- cgroups (no nativo)
- `sandbox-exec` (deprecated, no confiar)

**Estrategia:**
- Límites: rlimits + timeout + kill
- Filesystem: ejecutar en directorio controlado, confiar en permisos UNIX
- Network: **NO SE PUEDE HACER DEFAULT-DENY** sin kernel extension → documentar limitación
- Subprocess: monitoreo de pids hijos, kill tree al timeout

**Decisiones:**
- Documentar claramente que macOS no puede garantizar aislamiento de red ni filesystem estricto
- Recomendar ejecutar en entorno virtualizado si se requiere seguridad estricta

### Windows
**Mecanismos disponibles:**
- Job Objects (limits: CPU, memory, process count, I/O rate)
- `SetInformationJobObject` para límites

**NO disponibles:**
- cgroups/namespaces (concepto Linux)
- rlimits (concepto UNIX)

**Estrategia:**
- Límites: Job Objects con límites de CPU, memoria, pids
- Filesystem: ejecutar en directorio controlado + permisos NTFS
- Network: **NO SE PUEDE HACER DEFAULT-DENY** sin driver kernel/WFP → documentar limitación
- Subprocess: Job Objects propagate restrictions to child processes

**Decisiones:**
- Documentar que Windows no soporta aislamiento de red sin drivers
- Evaluar uso de Windows Sandbox API (solo Windows 10 Pro+) en fase futura

---

## 6. Architecture

### Módulos internos:

```
cmd/mcp-launcher/
  main.go                 # Entry point CLI

internal/
  config/
    config.go             # Carga configuración (archivo, env, flags)
    auth.go               # Gestión de tokens JWT

  registry/
    client.go             # Cliente HTTP para registry (resolve, download)
    types.go              # Estructuras de respuesta del registry
    auth.go               # Headers Authorization Bearer

  manifest/
    parser.go             # Parsing de manifest JSON
    validator.go          # Validaciones de coherencia manifest→bundle
    selector.go           # Selección de entrypoint por OS/arch

  cache/
    store.go              # Content-addressable cache por digest
    locking.go            # Locking concurrente para evitar race conditions
    eviction.go           # Política de eviction (LRU, tamaño máximo)

  executor/
    executor.go           # Interfaz de ejecución (STDIO, HTTP)
    stdio.go              # Ejecutor STDIO (stdin/stdout)
    http.go               # Ejecutor HTTP (proxy, healthcheck)

  sandbox/
    sandbox.go            # Interfaz de sandbox
    linux.go              # Implementación Linux (cgroups, rlimits, namespaces)
    darwin.go             # Implementación macOS (rlimits, timeouts)
    windows.go            # Implementación Windows (Job Objects)

  policy/
    policy.go             # Aplicación de políticas (network, env, subprocess)
    network.go            # Allowlist de dominios/IPs
    env.go                # Filtrado de variables de entorno

  audit/
    logger.go             # Auditoría local (JSON structured log)
    event.go              # Tipos de eventos (start, end, error)

  cli/
    root.go               # Comando raíz (cobra/urfave)
    run.go                # mcp run org/name@version
    pull.go               # mcp pull org/name@version (pre-download)
    cache.go              # mcp cache ls/rm
    login.go              # mcp login --token XXX
    doctor.go             # mcp doctor (diagnóstico de capacidades del OS)
```

### Flujo de ejecución (`mcp run org/name@version`):

1. **CLI** parsea args y carga config
2. **Registry client** resuelve referencia (`/v1/packages/:org/:name/resolve`)
3. **Cache** busca manifest/bundle por digest (si existe, skip download)
4. Si no existe, **Registry client** descarga manifest y bundle
5. **Cache** valida digest SHA-256 y almacena
6. **Manifest parser** valida y selecciona entrypoint por OS/arch
7. **Policy** aplica reglas de network allowlist, env, subprocess
8. **Sandbox** configura límites de recursos (cgroups/rlimits/Job Objects)
9. **Executor** ejecuta el proceso con transport (STDIO/HTTP)
10. **Audit logger** registra start event
11. Espera a que el proceso termine (o timeout)
12. **Audit logger** registra end event (exit code, duration)

---

## 7. Registry Integration Contract

### Endpoints del registry

#### `POST /v1/packages/:org/:name/resolve`
**Input (query param o body):**
```json
{
  "ref": "1.2.3",         // version, sha, o digest
  "platform": "linux",    // opcional: filtro de plataforma
  "arch": "amd64"         // opcional: filtro de arquitectura
}
```

**Output (200 OK):**
```json
{
  "manifest": {
    "digest": "sha256:abc123...",
    "url": "https://registry.example.com/manifests/sha256:abc123"
  },
  "bundle": {
    "digest": "sha256:def456...",
    "url": "https://registry.example.com/bundles/sha256:def456"
  }
}
```

**Headers esperados:**
- `Authorization: Bearer <JWT>` (si modo enterprise)
- `User-Agent: mcp-client/0.1.0`

**Comportamiento de redirects:**
- El launcher debe seguir redirects 3xx (presigned URLs de S3/GCS)
- Límite de redirects: 10

**Retries:**
- Reintentar en errores 5xx con exponential backoff (3 intentos)
- No reintentar en 4xx (salvo 429 Too Many Requests)

#### `GET /manifests/:digest` y `GET /bundles/:digest`
Descarga de artefactos. Pueden devolver:
- 200 OK con contenido
- 302/307 redirect a presigned URL
- 404 si no existe

**Validación:**
- Calcular SHA-256 del contenido descargado
- Comparar con digest esperado
- Rechazar si no coincide

### Autenticación

**Modo enterprise (JWT):**
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Claims esperados:**
- `sub`: usuario/servicio
- `org`: organización (para filtrar paquetes accesibles)
- `exp`: expiración

**Modo OSS (login opcional):**
```bash
mcp login --registry https://registry.example.com --token XXX
```
Token se guarda en `~/.mcp/auth.json`:
```json
{
  "registry": "https://registry.example.com",
  "token": "XXX",
  "expires_at": "2026-12-31T23:59:59Z"
}
```

### Caché de headers HTTP
El launcher debe respetar:
- `Cache-Control: max-age=3600` (caché de resolve responses)
- `ETag` / `If-None-Match` (validación de caché)

---

## 8. CLI UX

### Comandos principales

#### `mcp run <ref> [flags]`
Ejecuta un servidor MCP.

**Ejemplos:**
```bash
mcp run acme/hello-world@1.2.3
mcp run acme/hello-world@sha:abc123
mcp run acme/hello-world@digest:sha256:abc123...

# Con opciones
mcp run acme/tool@latest --timeout 60s --env-file .env --log-level debug
```

**Flags:**
- `--timeout duration`: timeout de ejecución (default: 5m)
- `--env-file path`: archivo con variables de entorno
- `--secret name=value`: secreto a pasar (se pasa como env var, no se loguea)
- `--log-level string`: nivel de log (debug, info, warn, error)
- `--no-cache`: forzar descarga sin usar caché
- `--registry string`: URL del registry (override config)

#### `mcp pull <ref>`
Pre-descarga un paquete sin ejecutar (útil para CI/CD).

```bash
mcp pull acme/tool@1.2.3
```

#### `mcp login`
Autenticación con el registry.

```bash
mcp login --token XXX
mcp login --registry https://custom-registry.com --token YYY
```

#### `mcp cache ls`
Lista artefactos en caché.

```bash
mcp cache ls
# Output:
# DIGEST                                          TYPE      SIZE     LAST USED
# sha256:abc123...                                manifest  4.2 KB   2 hours ago
# sha256:def456...                                bundle    12.5 MB  2 hours ago
```

#### `mcp cache rm <digest>`
Elimina un artefacto de la caché.

```bash
mcp cache rm sha256:abc123
mcp cache rm --all  # limpia toda la caché
```

#### `mcp doctor`
Diagnóstico de capacidades del sistema.

```bash
mcp doctor
# Output:
# [✓] OS: linux (amd64)
# [✓] Cgroups v2: available
# [✓] Network namespaces: available (requires CAP_NET_ADMIN)
# [✓] Seccomp: available
# [!] Running as non-root: network isolation limited
# [✓] Cache directory: /home/user/.mcp/cache (writable)
```

### Formato de logs

**Normal (info):**
```
[2026-01-18T10:30:00Z] Resolving acme/hello-world@1.2.3...
[2026-01-18T10:30:01Z] Resolved to sha256:abc123... (manifest), sha256:def456... (bundle)
[2026-01-18T10:30:01Z] Downloading manifest (4.2 KB)...
[2026-01-18T10:30:02Z] Downloading bundle (12.5 MB)...
[2026-01-18T10:30:05Z] Validating digests...
[2026-01-18T10:30:05Z] Starting MCP server (STDIO)...
[2026-01-18T10:30:05Z] Server running (PID 12345)
```

**Verbose (debug):**
```
[DEBUG] Config loaded from /home/user/.mcp/config.yaml
[DEBUG] Registry URL: https://registry.example.com
[DEBUG] Cache hit: manifest sha256:abc123
[DEBUG] Cache miss: bundle sha256:def456
[DEBUG] Applying resource limits: CPU=1000ms/s, Memory=512MB, PIDs=10
[DEBUG] Network policy: deny (no allowlist)
[DEBUG] Entrypoint: /bin/mcp-server --mode stdio
```

**Errores:**
```
[ERROR] Failed to resolve acme/hello-world@1.2.3: package not found (404)
[ERROR] Digest validation failed: expected sha256:abc123, got sha256:xyz789
[ERROR] Process killed by timeout (60s exceeded)
```

### Salida de errores
- Exit code 0: éxito
- Exit code 1: error de configuración
- Exit code 2: error de red/registry
- Exit code 3: error de validación (digest, manifest)
- Exit code 4: error de ejecución (proceso MCP falló)
- Exit code 5: timeout
- Exit code 124: señal de terminación (SIGTERM/SIGKILL)

---

## 9. Config

### Archivo de configuración

**Ubicación:** `~/.mcp/config.yaml` (o `MCP_CONFIG_PATH`)

**Ejemplo:**
```yaml
registry:
  url: https://registry.example.com
  timeout: 30s

cache:
  dir: ~/.mcp/cache
  max_size: 10GB
  ttl: 720h  # 30 días

executor:
  default_timeout: 5m
  max_cpu: 1000  # milicores (1 core)
  max_memory: 512M
  max_pids: 10
  max_fds: 100

security:
  network:
    default_deny: true
  subprocess:
    allow: false
  secrets:
    providers:
      - type: env
      - type: file
        path: ~/.mcp/secrets.yaml

audit:
  enabled: true
  log_file: ~/.mcp/audit.log
  format: json

log:
  level: info
  format: text  # text | json
```

### Variables de entorno (override config)

- `MCP_REGISTRY_URL`: URL del registry
- `MCP_REGISTRY_TOKEN`: token de autenticación
- `MCP_CACHE_DIR`: directorio de caché
- `MCP_LOG_LEVEL`: nivel de log (debug, info, warn, error)
- `MCP_TIMEOUT`: timeout por defecto

### Token storage

**~/.mcp/auth.json:**
```json
{
  "registries": {
    "https://registry.example.com": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expires_at": "2026-12-31T23:59:59Z"
    }
  }
}
```

**Permisos:** `0600` (solo lectura/escritura por owner)

---

## 10. Testing Strategy

### Unit tests
- Por módulo interno (config, registry, manifest, cache, executor, sandbox, policy, audit)
- Mocks para dependencias externas (HTTP client, filesystem, OS calls)
- Coverage objetivo: >80%

**Ejemplo:**
```go
// internal/manifest/validator_test.go
func TestValidateManifest_ValidSchema(t *testing.T) { ... }
func TestValidateManifest_InvalidEntrypoint(t *testing.T) { ... }
```

### Integration tests
- Registry mock (httptest) con endpoints /resolve, /manifests, /bundles
- Cache real en tmpdir
- Ejecución de proceso dummy (script bash/python que responde JSON-RPC)

**Ejemplo:**
```go
// internal/integration/run_test.go
func TestRunCommand_SuccessfulExecution(t *testing.T) {
  // Start mock registry
  // Run mcp run test/dummy@1.0.0
  // Assert process started, logs generated, audit recorded
}
```

### Tests por OS
- Build tags: `// +build linux`, `// +build darwin`, `// +build windows`
- Tests de sandbox específicos por plataforma

**Ejemplo:**
```go
// internal/sandbox/linux_test.go
// +build linux
func TestLinuxSandbox_CgroupsLimits(t *testing.T) { ... }
```

### Tests sin internet
- Todos los tests deben funcionar sin conexión
- Usar fixtures para manifests/bundles (archivos en `testdata/`)

### CI/CD
- GitHub Actions con matriz: [linux, macos, windows] × [amd64, arm64]
- Linters: golangci-lint
- Security scan: gosec

---

## 11. Non-goals

### Fuera de scope (al menos en v1.0):

1. **VM-based sandbox**: no usar Docker, Firecracker, gVisor, etc. (demasiado pesado)
2. **Análisis dinámico**: no inspeccionar syscalls en tiempo real, no strace/dtrace automático
3. **Compatibilidad con npm/pypi/docker**: solo formato MCP de mcp-registry
4. **Firma digital de bundles**: asumir que el registry es trusted, validar solo digest
5. **Hot reload**: si el manifest cambia, no recargar automáticamente (requiere restart)
6. **Multi-registry federation**: solo un registry a la vez (config global)
7. **GUI**: solo CLI (puede haber wrapper desktop en futuro)
8. **Telemetría remota**: solo auditoría local (no enviar métricas a servidor)

---

## 12. Implementation Plan

### Fase 1: Fundamentos (semana 1-2)
**Objetivo:** Estructura del proyecto + CLI básico + config

**Entregables:**
- [ ] Estructura de directorios (cmd/, internal/, docs/)
- [ ] Módulo `config`: carga de YAML + env vars
- [ ] Módulo `cli`: comando `mcp doctor` funcional
- [ ] Makefile con targets: build, test, lint, fmt
- [ ] CI básico (GitHub Actions)

**Definition of Done:**
- `mcp doctor` muestra capacidades del OS
- Tests unitarios pasan
- Build para linux/darwin/windows

---

### Fase 2: Registry Integration (semana 2-3)
**Objetivo:** Cliente de registry + descarga + validación de digest

**Entregables:**
- [ ] Módulo `registry`: cliente HTTP con resolve/download
- [ ] Autenticación JWT Bearer
- [ ] Seguimiento de redirects (presigned URLs)
- [ ] Validación de digest SHA-256
- [ ] Retries con exponential backoff

**Definition of Done:**
- `mcp pull acme/test@1.0.0` descarga manifest + bundle
- Digest validation rechaza artefactos corruptos
- Tests de integración con registry mock

---

### Fase 3: Cache (semana 3)
**Objetivo:** Content-addressable cache + locking

**Entregables:**
- [ ] Módulo `cache`: almacenamiento por digest
- [ ] Locking concurrente (evitar race conditions)
- [ ] Comando `mcp cache ls/rm`
- [ ] Eviction básico (LRU, size limit)

**Definition of Done:**
- Descargas repetidas usan caché (no re-download)
- Concurrent pulls no corrompen caché
- `mcp cache ls` muestra artefactos correctamente

---

### Fase 4: Manifest Parsing (semana 4)
**Objetivo:** Parser + validador + selector de entrypoint

**Entregables:**
- [ ] Módulo `manifest`: parser JSON
- [ ] Validación de schema (campos obligatorios)
- [ ] Selector de entrypoint por OS/arch
- [ ] Validación coherencia manifest→bundle

**Definition of Done:**
- Manifests inválidos son rechazados con error claro
- Entrypoint correcto se selecciona según plataforma
- Tests con fixtures de manifests válidos/inválidos

---

### Fase 5: Sandbox Linux (semana 4-5)
**Objetivo:** Límites + aislamiento en Linux

**Entregables:**
- [ ] Módulo `sandbox/linux`: rlimits + cgroups v2
- [ ] Network namespaces (default-deny)
- [ ] Filesystem isolation (bind mount)
- [ ] Subprocess restrictions (seccomp)

**Definition of Done:**
- Proceso MCP limitado en CPU/memoria/pids/fds
- Red aislada (solo loopback por defecto)
- Tests en VM Linux con cgroups habilitados

---

### Fase 6: Sandbox macOS (semana 5)
**Objetivo:** Límites realistas en macOS

**Entregables:**
- [ ] Módulo `sandbox/darwin`: rlimits + timeouts
- [ ] Filesystem strategy (directorio controlado)
- [ ] Documentación de limitaciones (no net isolation)

**Definition of Done:**
- Proceso MCP limitado en recursos básicos
- Timeout funciona correctamente (kill)
- `mcp doctor` documenta limitaciones de macOS

---

### Fase 7: Sandbox Windows (semana 6)
**Objetivo:** Job Objects en Windows

**Entregables:**
- [ ] Módulo `sandbox/windows`: Job Objects
- [ ] Límites de CPU, memoria, pids
- [ ] Documentación de limitaciones (no net isolation)

**Definition of Done:**
- Proceso MCP limitado via Job Objects
- Child processes heredan límites
- `mcp doctor` documenta limitaciones de Windows

---

### Fase 8: Executor (semana 6-7)
**Objetivo:** Ejecución de procesos MCP (STDIO + HTTP)

**Entregables:**
- [ ] Módulo `executor`: interfaz + stdio + http
- [ ] Ejecución STDIO (stdin/stdout JSON-RPC)
- [ ] Ejecución HTTP (proxy, healthcheck)
- [ ] Integración con sandbox

**Definition of Done:**
- `mcp run acme/test@1.0.0` ejecuta proceso correctamente
- Logs de stdout/stderr capturados
- Timeouts funcionan (kill process)

---

### Fase 9: Policy Enforcement (semana 7-8)
**Objetivo:** Network allowlist + env filtering + subprocess control

**Entregables:**
- [ ] Módulo `policy`: network allowlist
- [ ] Env var filtering (solo allowlist)
- [ ] Subprocess control (seccomp on Linux)

**Definition of Done:**
- Manifest con network allowlist se aplica correctamente
- Env vars no allowlisted se filtran
- Tests verifican enforcement

---

### Fase 10: Audit Logging (semana 8)
**Objetivo:** Auditoría local estructurada

**Entregables:**
- [ ] Módulo `audit`: structured JSON logger
- [ ] Eventos: start, end, error
- [ ] Redacción de secretos (no loguear valores)

**Definition of Done:**
- `~/.mcp/audit.log` contiene registros JSON
- Secretos no aparecen en logs
- Formato compatible con parsers (jq, Elasticsearch)

---

### Fase 11: CLI Polish (semana 9)
**Objetivo:** UX completa de comandos

**Entregables:**
- [ ] Comandos completos: run, pull, cache, login, doctor
- [ ] Help texts y ejemplos
- [ ] Progress bars (descarga de bundles grandes)
- [ ] Manejo de errores user-friendly

**Definition of Done:**
- Todos los comandos documentados en `--help`
- Errores claros (no stack traces en modo normal)
- `mcp run --help` muestra ejemplos

---

### Fase 12: Docs + Packaging (semana 10)
**Objetivo:** Documentación completa + release multi-plataforma

**Entregables:**
- [ ] docs/OVERVIEW.md
- [ ] docs/SECURITY.md
- [ ] docs/REGISTRY.md
- [ ] README.md con ejemplos
- [ ] Release automation (goreleaser)
- [ ] Binarios para linux/darwin/windows (amd64/arm64)

**Definition of Done:**
- Docs completas y revisadas
- Release automatizado en GitHub
- Binarios publicados (GitHub Releases)

---

## Checkpoints de Validación

Después de cada fase:
1. **Tests pasan**: unit + integration (si aplica)
2. **Linters pasan**: golangci-lint, gosec
3. **Builds multi-plataforma**: linux, darwin, windows
4. **Docs actualizadas**: si se añade funcionalidad, actualizar docs

---

## Criterios de Aceptación Global (v1.0)

- [ ] `mcp run acme/hello-world@1.0.0` descarga, valida y ejecuta correctamente
- [ ] Límites de recursos aplicados en linux/macos/windows
- [ ] Network default-deny funciona en Linux (documentado en otros OS)
- [ ] Caché evita re-downloads
- [ ] Audit log registra todas las ejecuciones
- [ ] Secretos no se exponen en logs
- [ ] Docs completas (OVERVIEW, SECURITY, REGISTRY)
- [ ] Binarios publicados para todas las plataformas

---

## Agentes Asignados

Ver perfiles detallados en `.claude/agents/`:
- 01-architect.md
- 02-registry-integration.md
- 03-manifest-validator.md
- 04-cache-store.md
- 05-sandbox-linux.md
- 06-sandbox-macos.md
- 07-sandbox-windows.md
- 08-cli-ux.md
- 09-audit-logging.md
- 10-docs.md

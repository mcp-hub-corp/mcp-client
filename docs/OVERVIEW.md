# MCP-Client Overview

## Qué es mcp-client

**mcp-client** es un launcher/ejecutor de servidores MCP que descarga, valida y ejecuta paquetes MCP desde un registry compatible (por defecto, **mcp-registry**).

## Relación con mcp-registry

mcp-client actúa como **cliente/consumidor** del registry mcp-registry. La arquitectura sigue un modelo cliente-servidor:

```
┌─────────────────┐                    ┌─────────────────┐
│                 │   HTTP/HTTPS       │                 │
│   mcp-client    │ ◄─────────────────►│  mcp-registry   │
│   (launcher)    │                    │   (servidor)    │
│                 │                    │                 │
└─────────────────┘                    └─────────────────┘
        │                                      │
        │ Descarga                             │ Provee
        │ Valida                               │ Almacena
        │ Ejecuta                              │ Distribuye
        ▼                                      ▼
  Servidor MCP                          Manifests/Bundles
```

### Responsabilidades de mcp-registry

El registry es responsable de:

- **Almacenar** manifests y bundles de paquetes MCP
- **Proveer API REST** para resolver referencias (org/name@version → digests + URLs)
- **Autenticar** clientes (JWT Bearer para modo enterprise)
- **Servir artefactos** directamente o vía redirects a S3/GCS (presigned URLs)
- **Garantizar integridad** mediante digests SHA-256 inmutables

### Responsabilidades de mcp-client

El launcher es responsable de:

- **Resolver referencias** consultando `/v1/packages/:org/:name/resolve`
- **Descargar** manifests y bundles desde las URLs provistas
- **Validar integridad** comparando SHA-256 del contenido descargado con digest esperado
- **Cachear localmente** en `~/.mcp/cache/` para evitar re-downloads
- **Parsear manifests** y seleccionar entrypoint correcto por OS/arquitectura
- **Aplicar sandbox** con límites de recursos (CPU, memoria, red, filesystem)
- **Ejecutar proceso** en modo STDIO o HTTP según manifest
- **Auditar** todas las ejecuciones localmente

### Flujo de comunicación típico

```
1. Usuario: mcp run acme/hello-world@1.2.3

2. mcp-client → mcp-registry:
   POST /v1/packages/acme/hello-world/resolve
   Body: {"ref": "1.2.3"}
   Headers: Authorization: Bearer <JWT>

3. mcp-registry → mcp-client:
   200 OK
   Body: {
     "manifest": {
       "digest": "sha256:abc123...",
       "url": "https://registry.example.com/manifests/sha256:abc123"
     },
     "bundle": {
       "digest": "sha256:def456...",
       "url": "https://cdn.example.com/bundles/sha256:def456"
     }
   }

4. mcp-client descarga manifest desde URL, calcula SHA-256, valida
5. mcp-client descarga bundle desde URL, calcula SHA-256, valida
6. mcp-client guarda en caché local (~/.mcp/cache/)
7. mcp-client parsea manifest, selecciona entrypoint
8. mcp-client aplica sandbox y ejecuta proceso
9. mcp-client audita inicio/fin en ~/.mcp/audit.log
```

## Independencia del registry

Aunque mcp-client está diseñado para trabajar con mcp-registry, **NO está acoplado a una implementación específica**:

- La URL del registry es configurable (`~/.mcp/config.yaml` o `--registry` flag)
- Cualquier servidor que implemente el contrato de API (ver `docs/REGISTRY.md`) es compatible
- El launcher solo requiere:
  - Endpoint `/v1/packages/:org/:name/resolve` que devuelva digests + URLs
  - Artefactos descargables (manifest JSON, bundle tar.gz)
  - Digests SHA-256 válidos

Esto permite:
- Usar registries privados/enterprise
- Mirror de registries públicos
- Desarrollo y testing con mocks locales

## Conceptos clave

### Manifest
Archivo JSON que describe el paquete MCP:
- Metadatos: nombre, versión, autor, licencia
- Entrypoints por plataforma (linux/darwin/windows) y arquitectura
- Transport: STDIO o HTTP
- Políticas de seguridad: allowlist de red, env vars, subprocess

### Bundle
Archivo tar.gz con el código ejecutable del servidor MCP. Puede contener:
- Binario nativo compilado
- Scripts (Python, Node.js) + dependencias vendored
- Assets adicionales

### Digest
Hash SHA-256 inmutable que identifica de forma única un manifest o bundle.
Formato: `sha256:abc123...` (64 caracteres hex)

### Cache
Almacenamiento local content-addressable en `~/.mcp/cache/`:
```
~/.mcp/cache/
  manifests/
    sha256:abc123.../manifest.json
  bundles/
    sha256:def456.../bundle.tar.gz
  metadata.db
```

## Modelo de seguridad

mcp-client implementa **aislamiento ligero** (no virtualización completa):

### Linux
- Límites: rlimits + cgroups v2
- Red: network namespaces (default-deny)
- Filesystem: bind mount + tmpfs
- Subprocess: seccomp para bloquear fork/exec

### macOS
- Límites: rlimits + timeouts
- Red: **NO DISPONIBLE** (sin network namespaces)
- Filesystem: directorio temporal + permisos UNIX
- Subprocess: monitoreo básico

### Windows
- Límites: Job Objects (CPU, memoria, pids)
- Red: **NO DISPONIBLE** (sin drivers WFP)
- Filesystem: directorio temporal + permisos NTFS
- Subprocess: heredan restricciones del Job Object

**Ver `docs/SECURITY.md` para detalles completos del threat model.**

## Próximos pasos

- Lee [`CLAUDE.md`](../CLAUDE.md) para el contexto completo del proyecto
- Revisa [`.claude/agents/`](../.claude/agents/) para los perfiles de agentes especializados
- Consulta [`docs/SECURITY.md`](SECURITY.md) para el modelo de seguridad detallado
- Consulta [`docs/REGISTRY.md`](REGISTRY.md) para el contrato de integración con el registry

---

**Nota**: Este documento es parte del setup inicial del proyecto. La implementación completa seguirá las fases definidas en `CLAUDE.md` sección "Implementation Plan".

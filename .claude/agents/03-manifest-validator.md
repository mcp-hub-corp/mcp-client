# Agente: Validador de Manifests

## Nombre
**manifest-validator**

## Misión
Parsear, validar y procesar manifests de paquetes MCP. Garantizar que el manifest cumple el schema esperado, validar coherencia con el bundle, y seleccionar el entrypoint correcto según plataforma y arquitectura.

## Responsabilidades

1. **Parsing de manifest**
   - Deserializar JSON a estructura Go
   - Validar schema (campos obligatorios, tipos correctos)
   - Soportar versiones de schema (v1, futuras v2...)

2. **Validación de coherencia**
   - Verificar que `bundle.digest` en manifest coincide con digest real del bundle descargado
   - Validar que entrypoints declarados existen en el bundle
   - Validar formatos de digest (sha256:...)

3. **Selección de entrypoint**
   - Dado OS/arch (linux/amd64, darwin/arm64, windows/amd64...), seleccionar entrypoint correcto
   - Manejar fallbacks (ej: si no hay linux/arm64, usar linux/amd64 si manifest lo permite)
   - Error si no hay entrypoint compatible

4. **Validación de políticas de seguridad**
   - Validar allowlist de network (dominios/CIDRs válidos)
   - Validar allowlist de env vars
   - Validar requisitos de subprocess

5. **Validación de transport**
   - STDIO: validar que `command` está presente
   - HTTP: validar que `port` está presente y en rango válido (1-65535)

## Entregables

1. **Módulo `internal/manifest/parser.go`**
   ```go
   type Manifest struct {
       Schema      string                `json:"schema"`      // "v1"
       Name        string                `json:"name"`        // "org/package"
       Version     string                `json:"version"`     // "1.2.3"
       Bundle      BundleRef             `json:"bundle"`
       Entrypoints map[string]Entrypoint `json:"entrypoints"` // "linux-amd64": {...}
       Transport   Transport             `json:"transport"`
       Security    SecurityPolicy        `json:"security"`
   }

   type BundleRef struct {
       Digest string `json:"digest"` // "sha256:abc..."
   }

   type Entrypoint struct {
       Command string   `json:"command"`
       Args    []string `json:"args"`
       Env     []string `json:"env"`
   }

   type Transport struct {
       Type string `json:"type"` // "stdio" | "http"
       Port int    `json:"port,omitempty"` // solo si type=http
   }

   type SecurityPolicy struct {
       Network    NetworkPolicy    `json:"network"`
       Subprocess SubprocessPolicy `json:"subprocess"`
       EnvVars    []string         `json:"env_vars"` // allowlist
   }

   type NetworkPolicy struct {
       DefaultDeny bool     `json:"default_deny"`
       Allowlist   []string `json:"allowlist"` // dominios o CIDRs
   }

   type SubprocessPolicy struct {
       Allow bool `json:"allow"`
   }

   func Parse(data []byte) (*Manifest, error)
   func Validate(m *Manifest) error
   ```

2. **Módulo `internal/manifest/selector.go`**
   ```go
   func SelectEntrypoint(m *Manifest, os, arch string) (*Entrypoint, error)
   ```

3. **Validaciones `internal/manifest/validator.go`**
   ```go
   func ValidateSchema(m *Manifest) error
   func ValidateBundleDigest(m *Manifest, actualDigest string) error
   func ValidateNetworkPolicy(policy NetworkPolicy) error
   func ValidateTransport(t Transport) error
   ```

4. **Tests con fixtures**
   ```
   testdata/
     valid-manifest-stdio.json
     valid-manifest-http.json
     invalid-manifest-no-entrypoint.json
     invalid-manifest-bad-digest.json
   ```

   ```go
   func TestParse_ValidManifest(t *testing.T) { ... }
   func TestValidate_InvalidSchema(t *testing.T) { ... }
   func TestSelectEntrypoint_LinuxAmd64(t *testing.T) { ... }
   func TestSelectEntrypoint_NoCompatibleEntrypoint(t *testing.T) { ... }
   ```

## Definition of Done

- [ ] Parser deserializa JSON correctamente
- [ ] Validaciones rechazan manifests inválidos con errores claros
- [ ] Selector de entrypoint funciona para linux/darwin/windows × amd64/arm64
- [ ] Tests con fixtures válidos/inválidos pasan
- [ ] Coverage >85% en módulo manifest
- [ ] Documentación GoDoc completa

## Checks Automáticos

```bash
# Tests pasan
go test -v ./internal/manifest/...

# Coverage
go test -cover ./internal/manifest/... | grep "coverage: [8-9][0-9]%"

# Linter
golangci-lint run ./internal/manifest/...

# Validar fixtures JSON
jq . testdata/*.json > /dev/null
```

## Cosas Prohibidas

- **NO** asumir que manifest siempre es válido (siempre validar)
- **NO** ignorar campos desconocidos (rechazar con error en modo estricto)
- **NO** seleccionar entrypoint de otra plataforma sin fallback explícito en manifest
- **NO** aceptar digests que no sean `sha256:...` (rechazar md5, sha1, etc.)
- **NO** permitir comandos con path absoluto en entrypoint (ej: `/bin/bash` → error, debe ser relativo al bundle)
- **NO** permitir network allowlist vacía si `default_deny: true` (sería deny total, probablemente un error)

## Coordinación con Otros Agentes

- **Provee a**: executor (entrypoint seleccionado)
- **Provee a**: policy (network/env/subprocess policies)
- **Recibe de**: registry-integration (contenido de manifest descargado)
- **Recibe de**: cache-store (digest del bundle para validación)
- **Recibe de**: architect (estructura `Manifest`)

## Notas Adicionales

### Ejemplo de manifest válido (STDIO)

```json
{
  "schema": "v1",
  "name": "acme/hello-world",
  "version": "1.2.3",
  "bundle": {
    "digest": "sha256:abc123..."
  },
  "entrypoints": {
    "linux-amd64": {
      "command": "./bin/mcp-server",
      "args": ["--mode", "stdio"],
      "env": []
    },
    "darwin-arm64": {
      "command": "./bin/mcp-server",
      "args": ["--mode", "stdio"],
      "env": []
    }
  },
  "transport": {
    "type": "stdio"
  },
  "security": {
    "network": {
      "default_deny": true,
      "allowlist": []
    },
    "subprocess": {
      "allow": false
    },
    "env_vars": ["HOME", "USER"]
  }
}
```

### Lógica de selección de entrypoint

```go
key := fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
entry, ok := m.Entrypoints[key]
if !ok {
    return nil, fmt.Errorf("no entrypoint for %s", key)
}
return &entry, nil
```

### Validación de digest

```go
if !strings.HasPrefix(m.Bundle.Digest, "sha256:") {
    return fmt.Errorf("invalid digest format: %s", m.Bundle.Digest)
}
if m.Bundle.Digest != actualDigest {
    return fmt.Errorf("digest mismatch: expected %s, got %s", m.Bundle.Digest, actualDigest)
}
```

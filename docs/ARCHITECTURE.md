# Architecture

Paradox Recon is **not** a wrapper that shells out to 30 tools.

It is a **pipeline**:

```
Target → Discovery → Diagnostics → Correlation → Risk findings → Report
```

## Layers

```
┌─────────────────────────────────────────────────────┐
│  CLI  (argparse subcommands)                        │
│  paradox-recon scan | plugins | init-config | menu  │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│  ScanEngine                                         │
│  resolve plugins → run ordered phases → correlate   │
└──────────┬─────────────────────────────┬────────────┘
           │                             │
┌──────────▼──────────┐       ┌──────────▼──────────┐
│  Plugins            │       │  Correlation        │
│  discovery/         │       │  cross-rules        │
│  diagnostics/       │       │  risk grade/score   │
│  each emits Finding │       └──────────┬──────────┘
└─────────────────────┘                  │
                              ┌──────────▼──────────┐
                              │  ScanReport         │
                              │  single schema      │
                              └──────────┬──────────┘
                                         │
                              ┌──────────▼──────────┐
                              │  Reporters          │
                              │  JSON · TXT · HTML  │
                              └─────────────────────┘
```

## Core types (`schema.py`)

| Type | Role |
|------|------|
| `Target` | Normalised host / URL / IP |
| `Finding` | Atomic observation with severity + score |
| `PluginResult` | One plugin’s output |
| `ScanReport` | Full pipeline artifact |

Every plugin **must** emit `Finding` objects. Free-form dicts are not part of the contract.

## Plugins

Plugins live in `paradox_recon/plugins/` and auto-register via `Plugin.__init_subclass__`.

| Plugin | Phase | Purpose |
|--------|-------|---------|
| `system` | discovery | Scanner host context |
| `network` | discovery | Public IP, port probe |
| `dns` | discovery | DNS records |
| `web` | diagnostics | HTTP, headers, tech, redirects |
| `tls` | diagnostics | Certificate health |
| `security` | diagnostics | Paths, CORS, cookies |
| `email` | diagnostics | SPF / DMARC / DKIM |

To add a capability: subclass `Plugin`, set `name` + `phase`, implement `run(target) → PluginResult`. No core changes required.

## Configuration

Precedence:

```
defaults < config file < PARADOX_* env < CLI flags
```

## Why this design

Most “recon scripts” accumulate features until they are unmaintainable dumps.

Paradox Recon treats recon as a **data pipeline**:

1. **Discover** surface
2. **Diagnose** each surface point
3. **Correlate** evidence into risk
4. **Report** in a stable schema

That is the difference between a hobby script and an engineering project.

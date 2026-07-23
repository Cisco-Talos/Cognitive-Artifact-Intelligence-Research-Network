---
name: vt-pivot
description: Run a VirusTotal pivot investigation from a seed hash, domain, or IP. Use when asked to pivot, investigate a sample, map campaign infrastructure, find variants, or trace a VT relationship.
---

Pivot-first investigation from a confirmed seed. Use when you have a known-interesting SHA256, domain, or IP and want to discover related samples, map infrastructure, or build out a campaign cluster.

All commands require the VT key in `.env`. All paths relative to repo root (`/home/ryan/CAIRN`).

## Seed type detection

`cairn pivot` auto-detects seed type:
- 64 hex chars → file (SHA256)
- Four dot-separated octets → IP  
- Anything else → domain

## Standard pivot sequence

### 1. Structural variants (start here for a file seed)

Find files that share PE structure with the seed — same compiler, packer, or vhash cluster:

```bash
source .venv/bin/activate
cairn pivot <sha256> --rel similar_files --limit 40 --min-detections 2
cairn summary
```

### 2. Infrastructure pivot (network IOCs the seed contacted)

```bash
cairn pivot <sha256> --rel communicating_files --limit 40 --min-detections 2
```

If the seed contacted domains or IPs, pivot those directly to find other files using the same infrastructure:

```bash
cairn pivot <domain>        # e.g. cairn pivot vozdyhan.up.railway.app
cairn pivot <ip>            # e.g. cairn pivot 66.33.22.78
```

### 3. Dropped / bundled files (lateral discovery)

```bash
cairn pivot <sha256> --rel dropped_files    # files dropped by this sample in sandbox
cairn pivot <sha256> --rel bundled_files    # files embedded within this sample
cairn pivot <sha256> --rel execution_parents  # files that executed this sample
```

### 4. Resolve embedded URL objects (no import — read only)

For a sample already in the corpus, resolve all embedded URL relationships:

```bash
cairn pivot-urls <sha256>
```

This does not import anything — use it to audit what infrastructure is baked into a specific sample.

### 5. Deep refresh on interesting finds

After pivoting, backfill behavioral sandbox data for high-value samples:

```bash
cairn refresh --sha256 <sha256> --behaviours
cairn refresh --sha256 <sha256> --sha256 <sha256> --behaviours   # multiple at once
```

### 6. Check corpus state after each pivot

```bash
cairn summary    # shows total samples, rule hits, filter/pivot provenance
```

---

## Available relationships per seed type

| Seed type | Relationship | What it finds |
|---|---|---|
| file | `similar_files` | Structurally similar PE files (same vhash cluster) |
| file | `communicating_files` | Files that contacted the same network IOCs |
| file | `dropped_files` | Files observed dropped by this sample in sandbox |
| file | `bundled_files` | Files embedded/contained in this sample |
| file | `execution_parents` | Files that executed this sample |
| domain | `communicating_files` | Files that contacted this domain in sandbox |
| ip | `communicating_files` | Files that contacted this IP in sandbox |

---

## Pivot exhaustion — when to stop

A pivot is exhausted when:
- `similar_files` returns only already-known samples or structurally unrelated files (different vhash, different compiler)
- `communicating_files` on all discovered domains/IPs returns 0 new samples
- `dropped_files` / `bundled_files` returns 0 results or only generic system DLLs

Document the exhaustion in the report's pivot record — e.g. "cairn pivot on all three loaders via `similar_files` returned 0 campaign results; structural similarity groups by packer, not payload."

---

## Gotchas

- **VT does not track loopback traffic** — `communicating_files` on a `127.0.0.1:7778` URL object returns 0. This is a platform limitation, not a bug.
- **`similar_files` groups by packer, not payload** — if the seed is UPX-packed, results will mostly be other UPX-packed files regardless of payload. Try the unpacked variant if available.
- **`bundled_files` returns ciphertext SHAs for encrypted payloads** — VT extracts overlays by SHA256, not by content. If the payload is encrypted, the extracted blob SHA will not match the decrypted payload SHA.
- **`min-detections` default is 0** — set `--min-detections 2` or higher to filter noise for discovery pivots. For infrastructure pivots where you're trying to confirm a single specific file, leave it at 0.
- **Railway.app is shared PaaS** — `communicating_files` on a Railway IP (66.33.22.0/23, ASN 400940) returns files for all tenants on that IP. Filter by domain, not IP, when pivoting Railway infrastructure.
- **Rate limit** — default 4 req/min, 500 req/day. `--deep` costs 2 API calls per discovered sample. At 40 samples per pivot with `--deep`, one pivot run costs ~80 API calls.

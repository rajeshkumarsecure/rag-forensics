# Memory Forensics Automation & RAG-Driven Analysis

## Overview
This repository provides an end-to-end workflow for:
1. Generating and executing Metasploit payloads in a controlled lab and capturing Linux VMware memory snapshots (`.vmem`/`.vmsn`).
2. Extracting and normalizing Indicators of Compromise (IoCs) from dumps and ingesting them into Qdrant with Azure OpenAI embeddings.
3. Acquiring Windows memory dumps using WinPmem (`.raw`) and analyzing both Linux/Windows dumps with Retrieval-Augmented Generation (RAG), producing strict JSON + HTML incident reporting.

This project is intended for **authorized research and lab experimentation only**.

## High-Level Architecture

### 1) Automatic Forensics Pipeline (Windows host + VMs)
- Runs on Windows with VMware Workstation Pro.
- Attacker VM (Kali): payload generation + Metasploit handler orchestration.
- Victim VM (Ubuntu): payload execution target + memory snapshot source.
- Per payload workflow:
  1. Generate payload on attacker via `msfvenom`.
  2. Revert victim to clean snapshot.
  3. Transfer payload and execute on victim.
  4. Start/verify reverse or bind handler session.
  5. Capture VMware snapshot and copy `.vmem` + `.vmsn` for analysis (**Linux dumps only**).
  6. Cleanup handler/session and snapshot artifacts.

### 1.1) Windows Dump Acquisition (WinPmem)
- Windows memory dumps are generated with `go-winpmem-4.1-rc1_test_signed.exe`.
- Command:
  - `go-winpmem-4.1-rc1_test_signed.exe acquire <<dump_file_name.raw>>`
- In this release, the driver is test-signed; test signing must be enabled:
  1. Open elevated Command Prompt and run: `bcdedit /set testsigning on`
  2. Reboot
  3. Run the WinPmem tool and acquire the dump
  4. Revert after testing: `bcdedit /set testsigning off`
- Release page: https://github.com/Velocidex/WinPmem/releases

### 2) IoC Normalization + Ingestion (Volatility + Qdrant + Embeddings)
- Volatility plugins extract network/process/memory indicators.
- Indicators are normalized into payload text + tags + structured facets.
- Embeddings are generated using Azure OpenAI and upserted into Qdrant.
- Payload indexes are created for selected indicator fields.

### 3) RAG-Driven Analysis of New Dump
- New dump is parsed with the same extraction logic.
- Candidate prior cases are retrieved from Qdrant (dense search).
- Results are re-ranked using dense + BM25 + set similarity.
- LLM receives strict forensic prompt and returns JSON response.
- HTML report is rendered from JSON for analyst review.

## What’s Current (Feb 2026)
- RAG analysis supports **both Linux and Windows** memory dumps (auto-detected with Volatility plugins).
- Ingestion and analysis use a **hybrid ranking pipeline**:
  - Dense vector similarity (Qdrant)
  - BM25 lexical scoring
  - Indicator set similarity (Jaccard/precision)
- HTML reporting includes classification, MITRE mapping, observed indicators, reasoning, and recommendations.
- Qdrant payload indices are created for selected indicator facets during collection setup.

## Features
- Automated multi-payload memory acquisition with snapshot lifecycle handling.
- Reverse and bind shell payload handling with IPv4/IPv6-aware configuration.
- Volatility-based extraction for network, process, maps, and suspicious strings.
- Windows suspicious-process workflow with process dump + byte/string matching.
- Schema-agnostic indicator tokenization for robust retrieval/ranking.
- Strict JSON-based LLM output contract and HTML report generation.

## Repository Structure
```text
README.md
automatic_forensics_pipeline/
  payload_generation.py
  memory_dump_generation.py
  pipeline_config.json

rag_driven_forensic_analysis/
  analyze_new_memory_dump.py
  normalize_and_ingest_into_vector_db.py
  memory_extraction_functions.py
  rag_utils.py
  html_utils.py
  processing_config.json
  requirements.txt
  images/
    clean.png
    default.png
    ioc.png
    malware.png
    reasoning.png
    search.png
    security_recomdation.png
    suspicious.png
    technical_details.png

qdrant_dump/
  memory_forensics_analysis-3383796559103186-2025-11-03-18-23-42.snapshot
```

---

## Prerequisites

### Infrastructure
- Windows 11 host with VMware Workstation Pro (for dump generation pipeline).
- Kali attacker VM and Ubuntu victim VM reachable over SSH.
- Existing snapshots on victim VM for clean + forensics cycle.

### Tooling
- Python:
  - Pipeline scripts: Python `3.12.x` (Windows host)
  - RAG scripts: Python `3.10+` (Linux recommended)
- Metasploit on attacker (`msfvenom`, `msfconsole`, `tmux`)
- WinPmem for Windows dump acquisition (`go-winpmem-4.1-rc1_test_signed.exe`)
- Volatility3 CLI available as `vol` on analysis machine
- Qdrant running locally
- Azure OpenAI deployments:
  - Embedding: `text-embedding-3-large`
  - Chat: `gpt-5-chat`

### Python dependencies (RAG)
Install from `rag_driven_forensic_analysis/requirements.txt`:
```bash
pip install -r rag_driven_forensic_analysis/requirements.txt
```
Install HTML report dependency:
```bash
pip install pillow
```

If Volatility3 is not already installed:
```bash
wget https://github.com/volatilityfoundation/volatility3/archive/refs/tags/v2.26.2.tar.gz
tar -xvf v2.26.2.tar.gz
cd volatility3-2.26.2
pip install --user -e ".[full]"
```

Place the symbol files matching your target dump OS/kernel into the Volatility symbols directory before analysis.

> Note: NLTK stopwords are downloaded automatically on first run if missing.

### SSH key setup (for pipeline automation)
From Windows host:
```bash
ssh-keygen -t rsa
ssh-copy-id <victim_user>@<victim_ip>
ssh-copy-id <attacker_user>@<attacker_ip>
```
Ensure both hosts are reachable over SSH and present in `known_hosts`.

---

## Configuration

### 1) Pipeline config
File: `automatic_forensics_pipeline/pipeline_config.json`

Configure VMware paths, VM snapshots, SSH/IP credentials, payload list, and interfaces.

Important fields to validate:
- VMware paths: `ubuntu_vm_folder`, `ubuntu_vm_file`, `Ubuntu_vmsd_file`
- Snapshot names: `clean_snapshot`, `forensics_snapshot`
- Victim and attacker credentials/IP/interface fields
- Payload details: `payload_dir`, `payloads`, `msfvenom_path`, `payload_name`

#### Important current behavior
- `memory_dump_generation.py` reads `pipeline_config.json`.
- `payload_generation.py` currently reads **`config.json`** from `automatic_forensics_pipeline/`.

If you want to run `payload_generation.py` without code changes, create a copy:
```bash
cp automatic_forensics_pipeline/pipeline_config.json automatic_forensics_pipeline/config.json
```

### 2) RAG config
File: `rag_driven_forensic_analysis/processing_config.json`

Key fields:
- Azure: `endpoint_url`, `open_ai_api_key`, `embedding_model`, `gpt_model`, `api_version`
- Qdrant: `qdrant_host`, `qdrant_port`, `qdrant_collection`
- Dump map: `memory_dumps_classification`
- Heuristics: `suspicious_strings`, recommendations

Important fields to validate:
- `memory_dumps_dir` and `memory_dumps_classification`
- `classification_source`
- `RemoteShellRecommendations`

Environment overrides supported by scripts:
```bash
export ENDPOINT_URL="https://<your-endpoint>.openai.azure.com/"
export AZURE_OPENAI_API_KEY="<key>"
export DEPLOYMENT_NAME="<deployment-name>"
```

> Current script behavior: `DEPLOYMENT_NAME` is used for both embedding and chat deployment overrides. If your chat and embedding deployments differ, prefer configuring both in `processing_config.json` and avoid setting `DEPLOYMENT_NAME`.

---

## Usage

## A) Generate payloads and capture memory dumps (Windows host)

### 1. Generate payload artifacts
```bash
python automatic_forensics_pipeline/payload_generation.py
```
Payloads are generated on attacker VM under configured `payload_dir`.

### 2. Execute payload cycle and snapshot victim memory
```bash
python automatic_forensics_pipeline/memory_dump_generation.py
```
Per payload, script performs:
- Revert victim to clean snapshot
- Start reverse/bind handler
- Transfer + execute payload
- Verify connection
- Capture Linux VM snapshot (`.vmem`, `.vmsn`)
- Copy dumps to `automatic_forensics_pipeline/memory_dumps/`

### 3. Generate Windows memory dump with WinPmem
Use WinPmem on the Windows target to acquire `.raw` dump files:
```bash
go-winpmem-4.1-rc1_test_signed.exe acquire <<dump_file_name.raw>>
```

Test-signing requirement for this WinPmem release:
```bash
bcdedit /set testsigning on
```
Reboot, run acquisition, then revert:
```bash
bcdedit /set testsigning off
```

WinPmem release reference:
- https://github.com/Velocidex/WinPmem/releases

### 4. Make dumps available to RAG ingestion
Current default ingestion path is `memory_dumps_dir: "memory_dumps"` under `rag_driven_forensic_analysis/` when run from that folder.

Choose one option:
- Copy dumps into `rag_driven_forensic_analysis/memory_dumps/`
- Or set absolute/relative `memory_dumps_dir` in `processing_config.json` to point to `automatic_forensics_pipeline/memory_dumps/`

## B) Ingest historical dumps into Qdrant (analysis machine)

Run from inside `rag_driven_forensic_analysis/` (required by current relative config path usage):
```bash
cd rag_driven_forensic_analysis
python normalize_and_ingest_into_vector_db.py
```

## C) Analyze a new dump with RAG

Also run from `rag_driven_forensic_analysis/`:
```bash
cd rag_driven_forensic_analysis
python analyze_new_memory_dump.py /path/to/new_dump.vmem
```
Outputs:
- Structured JSON to stdout
- HTML report: `<dump_basename>_pid_<pid>_report.html`

## D) Quick start summary
1. Configure pipeline + RAG JSON config files.
2. Generate payloads.
3. Acquire Linux dumps via VMware snapshot pipeline and Windows dumps via WinPmem.
4. Ensure `memory_dumps_dir` points to your dumps.
5. Ingest historical data into Qdrant.
6. Analyze a fresh dump and review JSON/HTML outputs.

---

## Qdrant Setup (Persistent Docker)
Create storage volume:
```bash
docker volume create qdrant_storage
```
Run container:
```bash
docker run -d \
  --name qdrant \
  -p 6333:6333 \
  -p 6334:6334 \
  -v qdrant_storage:/qdrant/storage \
  qdrant/qdrant
```

## Restore sample collection snapshot
```bash
curl -X PUT "http://localhost:6333/collections/memory_forensics_analysis/snapshots/recover?wait=true" \
  -H "Content-Type: application/json" \
  -d '{
    "location": "file:///qdrant/snapshots/memory_forensics_analysis/memory_forensics_analysis-3383796559103186-2025-11-03-18-23-42.snapshot",
    "priority": "snapshot"
  }'
```
Verify:
```bash
curl -s "http://localhost:6333/collections" | jq
```

If your Qdrant instance has API-key protection enabled, include `-H "api-key: <api_key>"` in both requests.

---

## Detection and Scoring Logic
- Network features from Volatility output (TCP/UDP/SCTP, direction heuristics, suspicious ports).
- Process/memory-map features including RWX anomalies and anonymous mappings.
- YARA-like suspicious string matching for shellcode/meterpreter indicators.
- Schema-agnostic tokenization of indicators for robust matching.
- Re-ranking combines dense, BM25, and indicator set overlap.

## Output schema details
Typical response includes:
- `observation`: high-level analyst-facing points.
- `Technical Details`: concrete artifacts (ports, process patterns, memory findings).
- `Threat`, `classification`, `confidence`.
- `Tactics`, `Techniques`, and their reason fields.
- `matched_rag_indicators`: overlap between query and retrieved cases.
- `Security Recommendations`: actionable response steps.

## LLM Output Contract
Expected strict JSON fields include:
- `observation`
- `Technical Details`
- `Threat`, `classification`, `confidence`
- `Tactics`, `Techniques`, reasons
- `matched_rag_indicators`
- `Security Recommendations`

---

## Troubleshooting
| Symptom | Likely Cause | Resolution |
|---|---|---|
| `processing_config.json` not found | Script launched from repo root | `cd rag_driven_forensic_analysis` before running RAG scripts |
| `vol` command not found | Volatility not on PATH | Install Volatility3 and expose `vol` |
| Empty IoCs | Plugin/profile mismatch | Validate dump type and Volatility plugin compatibility |
| Qdrant upsert/search errors | Collection mismatch / service down | Check Qdrant status, host/port, and embedding consistency |
| Non-JSON LLM output | Model drift/timeout | Re-run and verify endpoint/model config |
| Payload generation fails to load config | `config.json` missing | Copy `pipeline_config.json` to `automatic_forensics_pipeline/config.json` |

## Known Limitations
- Port/direction heuristics can misclassify uncommon network patterns.
- Advanced injection techniques may evade RWX/string heuristics.
- MITRE mapping and confidence are LLM-assisted and need analyst validation.
- Qdrant authentication is not enabled by default in local examples.

## Extensibility ideas
- Add plugin support for additional artifacts (files, registry, persistence traces).
- Introduce provenance/version tracking for each ingested point.
- Add CLI flags for selective pipeline stages and parallel processing.
- Add stricter schema validation + retry policy for non-JSON model outputs.

---

## Security & Ethics
- Use only in isolated lab environments with explicit authorization.
- Treat memory dumps as sensitive artifacts.
- Remove payloads, credentials, and temporary dumps after experiments.

## Authors
Project created by:
- Rajesh Kumar Natarajan (@rajeshkumarsecure)
- Srinivasan Govindarajan (@svsrinigk)
- Pranjal Gupta (@pranjal2209)

## Disclaimer
For educational and research use only. Authors are not responsible for misuse.

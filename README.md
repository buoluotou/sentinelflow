# SentinelFlow

An AI-assisted security alert orchestration and incident response platform.

## Overview

SentinelFlow is designed to help security operations centers (SOCs) efficiently manage, analyze, and respond to security alerts. It provides intelligent alert ingestion, normalization, deduplication, and incident correlation capabilities.

## Architecture

```
Scenario Simulator  →  SentinelFlow Backend (FastAPI)  →  PostgreSQL  →  React Web Console
```

## Features (Phase 1)

- Alert Ingestion via HTTP/JSON
- Event Normalization
- Deduplication & Aggregation
- Basic Incident Management
- React Web Console (Dashboard, Alerts, Incidents)

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker Desktop (for PostgreSQL)

### Setup

```bash
# Backend
cd backend
python -m venv .venv
# Windows PowerShell:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -r requirements/base.txt
uvicorn app.main:app --reload

# Frontend
cd frontend
npm install
npm run dev

# PostgreSQL
docker compose up -d postgres
```

## Project Structure

```
sentinelflow/
├── backend/          # FastAPI backend
├── frontend/         # React + TypeScript frontend
├── simulator/        # Scenario simulator
├── integrations/     # External platform adapters
├── infrastructure/   # Docker, scripts
├── docs/             # Documentation
└── tests/            # Integration & E2E tests
```

## License

MIT License. See [LICENSE](LICENSE).

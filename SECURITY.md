# Security Policy

## Repository Hygiene

- Never commit `.env` files — it is git-ignored. Use `.env.example` as the template.
- Never commit credentials, API keys or tokens. All secrets are read from environment variables at runtime.
- Docker Compose reads the PostgreSQL password from the environment; change the default `change_me` value before running locally.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in SentinelFlow, please do **not** open a public issue.

- Email: report privately to the maintainers with:
  - a description of the issue,
  - reproduction steps or a proof of concept,
  - affected component (backend / frontend / simulator / infrastructure).

We aim to acknowledge reports within 48 hours and to publish fixes for confirmed issues as soon as practical.

## Scope

Only assets in this repository are in scope. Upstream projects (Wazuh, Shuffle, TheHive, Ollama) have their own security policies.

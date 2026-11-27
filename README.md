# Sentinel — Security Event API

A FastAPI backend that ingests security events, detects brute-force patterns, raises alerts, and keeps an audit trail. Built to demonstrate real backend engineering with a security domain.

[![CI](https://github.com/arnavj10321/-sentinel-backend/actions/workflows/ci.yml/badge.svg)](https://github.com/arnavj10321/-sentinel-backend/actions/workflows/ci.yml)

## What it does

- JWT register/login with bcrypt password hashing
- Role-based access control (`user` / `admin`)
- Event CRUD with filtering, pagination, and sorting
- Detection rule: 5 `failed_login` events from the same IP in 10 minutes → alert
- Alert acknowledge / resolve workflow
- Redis rate limiting on `/auth/login`
- Append-only audit log
- Security headers on every response

## Stack

Python 3.13 · FastAPI · SQLAlchemy 2.0 · Alembic · PostgreSQL · Redis · JWT · bcrypt · pytest · ruff · mypy · bandit · pip-audit · Docker · GitHub Actions

## Run locally

```powershell
docker compose up -d
.\.venv\Scripts\Activate.ps1
alembic upgrade head
python seed_admin.py
python seed.py
uvicorn main:app --reload

Tests
pytest -q
ruff check .
mypy .
bandit -r . -x .venv,tests -ll
pip-audit -r requirements.txt



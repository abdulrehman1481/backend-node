# BDD Node Backend

This is the Node.js/TypeScript replacement backend for the BDD project.

## Stack

- Express + TypeScript
- Prisma ORM
- PostgreSQL (shared with Django) via `DATABASE_URL=postgresql://...`
- JWT auth (`/api/auth/token/`, `/api/auth/token/refresh/`)

## Quick Start

1. Install dependencies:

```bash
npm install
```

2. Configure env:

```bash
copy .env.example .env
```

3. Generate Prisma client + create database schema:

```bash
npm run prisma:generate
```

Do not run `npm run prisma:push` against the shared Django database. The database schema is managed by Django migrations in `backend/`.

4. Run API:

```bash
# from backend-node/
npm run start

# from workspace root (d:/appdev/bdd)
npm --prefix backend-node run start
```

Server default: `http://127.0.0.1:8000`
API base: `http://127.0.0.1:8000/api`

## Frontend + Mobile Connection

No API path changes are required because this backend mirrors the existing `/api/*` contract.

- Portal (`bdd-portal`):
  - `NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8000/api`
- Mobile (`bdd-mobile`):
  - Android emulator: `EXPO_PUBLIC_API_BASE_URL=http://10.0.2.2:8000/api`
  - Physical device: set your LAN IP, e.g. `http://192.168.1.20:8000/api`

## Implemented Route Parity

- Auth: register, token, refresh, me
- Profiles: donor/hospital get+update
- Requests: list, detail, create, status update
- Request actions and comments
- Matching trigger endpoint
- Donor radar and pinging
- Donor inbox + history + respond
- Hospital summary + sent pings + delete pending ping
- Donor feed + eligibility + summary
- Medical center directory
- Health check

## Development

```bash
npm run dev
npm run typecheck
```

## Notes

- This backend is intentionally API-compatible with current web/mobile clients.
- Prisma models in `prisma/schema.prisma` are mapped to existing Django tables (for example, `core_user`, `core_bloodrequest`, `core_donorprofile`).

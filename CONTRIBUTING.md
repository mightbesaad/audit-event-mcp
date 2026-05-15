# Contributing

## Development setup

```sh
npm install
npm test         # all tests must pass
npm run lint     # Biome — no warnings
npm run typecheck
```

## Code changes

- Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`
- One concern per PR — refactor and feature in the same PR is a re-roll
- New dependencies require discussion before opening a PR
- Pre-commit hook runs Biome and blocks commits with `.only` in tests

## What gets rejected

- New dependencies added without prior discussion
- PRs that touch more than one concern
- Direct `wrangler deploy` without a clean `git status` — see CLAUDE.md for the deploy safety rule

# Contributing to FuseViz

## Getting Started

1. Clone the repo
2. Install dependencies: `pnpm install`
3. Copy `.env.example` to `.env`
4. Start the dev server: `pnpm dev`

## Development

- **Frontend**: Next.js 16 + React 19 + Tailwind v4 + shadcn/ui
- **Backend**: C++20 daemon (build with CMake) or simulation mode

## Code Style

- TypeScript strict mode enabled
- ESLint with Next.js recommended rules
- C++20 with `-Wall -Wextra -Wpedantic`

## Pull Requests

1. Create a feature branch from `main`
2. Make your changes
3. Ensure `pnpm lint` and `pnpm build` pass
4. Submit a PR with a clear description

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat: add new feature`
- `fix: bug fix`
- `docs: documentation only`
- `chore: maintenance`

## Reporting Issues

Open an issue with:
- Description of the problem
- Steps to reproduce
- Expected vs actual behavior

# Engineering toolchain

The development baseline is CPython 3.12 and Node.js 24. Use the same
hash-checked Python lock and exact npm lockfiles in local development and CI.
The Antigravity plugins run in the engineering session. The architecture
checks in GitHub Actions run as ordinary commands.

## Tool versions and configuration

| Tool | Version and installation | Functional check |
| --- | --- | --- |
| [Ponytail](https://github.com/DietrichGebert/ponytail) | Antigravity plugin 5.3.3, reused | `agy plugin list --json` lists `ponytail` (full by default), review, audit, debt, gain and help. |
| [CodeGraph](https://github.com/colbymchenry/codegraph) | Global npm 1.6.4, reused. The index lives in ignored `.codegraph/`. | `codegraph init`, `status`, `sync`, `cycles`, `callers`, `impact` and MCP `codegraph_explore`. |
| [RTK](https://github.com/rtk-ai/rtk) | CLI 1.2.1 and Antigravity plugin 1.0.0, reused | `rtk --version`, `--help`, `gain`, `gain --daily`, `gain --history`, and explicit command prefixes. |
| [Agent Skills](https://github.com/addyosmani/agent-skills) | Antigravity plugin 0.6.18, reused | `agy plugin list --json` lists 26 skills, including the implementation, interface design, testing, review, supply-chain and frontend skills. |
| [Context7](https://github.com/upstash/context7) | Existing enabled `npx -y @upstash/context7-mcp` registration, reused | `resolve-library-id` and `query-docs` returned Import Linter, Dependency Cruiser and SQLAlchemy documentation. The existing launcher resolves the npm version at launch. |
| [Playwright MCP](https://github.com/microsoft/playwright-mcp) | Global npm 0.0.86, reused with `--isolated`. Playwright Test stays at 1.65.1 in the frontend lock. | Navigate, snapshot, click and keyboard actions exercised the evidence panel against synthetic loopback data. |
| [Matt Pocock skills](https://github.com/mattpocock/skills) | Reused `improve-codebase-architecture` and `codebase-design`. Installed the missing `domain-modeling` dependency with Skills CLI 1.9.1. | The two architecture skills and domain modeling resolve from the existing Antigravity user skill directory. |
| [Import Linter](https://github.com/import-linter/import-linter) | 2.17, backend hash lock | `lint-imports` reads [backend contracts](../backend/pyproject.toml). The contracts keep evidence schemas below API and infrastructure adapters and keep DB records below their services. |
| [Dependency Cruiser](https://github.com/sverweij/dependency-cruiser) | 18.9.0, frontend lock | `npm run check:architecture` checks TypeScript cycle, resolution, test and component boundaries. Infrastructure uses a separate TypeScript/CDK build and synthesis gate. |
| [Hypothesis](https://github.com/HypothesisWorks/hypothesis) | 6.170.17, backend hash lock | Bounded deterministic examples exercise JSON, content identity, evidence byte accounting and cleanup, coverage, and real API idempotency. |
| [Pyright](https://github.com/microsoft/pyright) | 1.1.414, global npm CLI and an exact CI pin | `pyright --version`, `--help` and basic checking of selected Python 3.12 asset, content, intake, coverage and operations contracts. |

The dependency review confirmed all 43 existing Python pins and their
distribution hashes and all existing frontend version and integrity pairs.
Dependency Cruiser added 41 frontend lock entries. The infrastructure lock
retains its separate native TypeScript, CDK test and synthesis checks.

The private API has no published OpenAPI endpoint, and several current
authenticated route annotations describe only generic dictionaries. Native
HTTP and PostgreSQL tests exercise the role, CSRF, validation and response
paths directly. Schemathesis remains deferred until typed response schemas
and authenticated fixtures give schema generation a distinct acceptance target.

## Reproduce the architecture checks

```powershell
codegraph status
codegraph sync
codegraph cycles

Set-Location backend
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e '.[dev]'
python -m pip check
lint-imports
npx --yes pyright@1.1.414 --pythonpath (Get-Command python).Source
python -m pytest -q

Set-Location ../frontend
npm ci --no-audit --no-fund
npm run check:architecture
npm run build
npm test
npm run test:e2e
```

The commands assume the Python virtual environment is active. On Windows,
if matching native Chromium is already installed outside an isolated shell's
default cache, point `PLAYWRIGHT_BROWSERS_PATH` at that installation before
running the browser suite. Integration tests need the disposable PostgreSQL
roles, grants and Alembic head used by [backend CI](../.github/workflows/backend.yml).
See [supply-chain operations](python-supply-chain.md) for the lock generation
and SBOM commands and [case evidence pagination](case-evidence-pagination.md)
for the PostgreSQL comparison workload.

## Tool installation commands used

```powershell
agy --version
agy --help
agy plugin list --json
agy mcp list
rtk --version
rtk gain --daily
rtk gain --history
codegraph init
npx --yes skills@1.9.1 add mattpocock/skills --list
npx --yes skills@1.9.1 add mattpocock/skills --global --agent antigravity --skill domain-modeling --copy --yes
rtk npm install --global --ignore-scripts --no-audit --no-fund pyright@1.1.414
rtk npm --prefix frontend install --save-dev --save-exact --package-lock-only --ignore-scripts --no-audit --no-fund dependency-cruiser@18.9.0
rtk npm --prefix frontend ci --no-audit --no-fund
```

The Import Linter and Hypothesis installation used the regenerated Python
lock with `pip install --require-hashes`. The local Playwright Test command
was `playwright test --workers=1 --reporter=list --global-timeout=90000`
through the project-local executable. Isolated Playwright MCP exercised the
evidence view with a click and keyboard navigation. The ignored synthetic
fixture served the compiled console on loopback.

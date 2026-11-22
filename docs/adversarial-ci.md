# Aegentra adversarial CI — enforced automated gates

The GitHub Actions workflows run native Python, Node.js, Chromium and
PostgreSQL. **No Docker, Kubernetes, live EC2 mutation, deployment or
customer code execution** is involved.

## Trigger and trust boundary

- Every `main` push and pull request runs the backend, frontend, CDK and
  adversarial security workflows. Security also runs weekly for newly
  disclosed dependency advisories.
- All external Actions references are pinned to specific reviewed commit
  hashes. The policy scanner rejects unpinned future actions, permissive
  write tokens, untrusted event triggers, suppressed step failures,
  self-hosted runners, and missing adversarial test entrypoints.
- The default workflow token is read-only. Only the isolated CodeQL job
  has `security-events: write` to upload findings; it cannot deploy.
- High-confidence credential patterns are scanned across tracked text
  without echoing suspected secret values in logs. This scan is **not** a
  replacement for a dedicated full-history/entropy secret scanner.

## Automated hostile-input regression

`scripts/ci_security_gate.py` enforces a curated native security test
matrix across watchdog, physical custody, AMI and network admission,
encrypted raw EBS attachment, preflight, double-pass detach, guest
protocol, signed reviews, gateway/veto and origin binding. Its JUnit
oracle requires at least 75 executed cases, every mandatory test module,
and zero skipped, errored or failed cases. The separate backend job runs
the actual native PostgreSQL role, RLS, lease and journal integration
tests. CI does not mutate an AWS account.

## Dependency and static analysis

- `pip-audit --strict backend` blocks known advisory findings in the
  Python project's current resolved dependency tree.
- Frontend and infrastructure dependency graphs are audited with
  `npm audit --audit-level=high`; any high or critical advisory fails
  that job. The entire tree is resolved from the reviewed,
  **committed `package-lock.json`** via `npm ci`. npm advisory analysis
  is executed with lifecycle scripts disabled.
- Python and JavaScript/TypeScript CodeQL analysis runs the
  `security-extended` and `security-and-quality` query suites. A
  successful CodeQL upload means the analysis ran; **it does not on its
  own prove there are zero alerts**. Review code-scanning alerts in
  GitHub's Security tab.
- Lockfile artifacts remain available briefly from the security run
  for comparing installed dependency resolutions. They do not replace
  committed lockfiles.

## External gates and coverage gaps

No automated CI can exercise or prove every possible attack or eliminate
all vulnerabilities. This repository does not yet have independently
qualified adversarial F01–F15 production fixture evidence, real isolated
AWS cross-account IAM/network/link-local/IMDS drills, hardware-backed
reviewer and witness signing, customer TLS and origin-bypass tests,
destructive EBS disposal verification or external immutable audit custody.
A deterministic, reviewed Python dependency lock and a formal SBOM/
signed artifact provenance gate are still outstanding.

GitHub branch protection, required-check configuration, dependency
updates, secret scanning and deployment environment approvals must also
be verified by a repository administrator in GitHub settings; the
read-only workflow does not silently configure or claim those controls.

**Protected production: NO-GO.** Do not turn security workflow green
into an ENFORCED release authorization.

# AuthClaw Coding Rules

## Architecture
- Buy, do not build engines: use proven libraries/frameworks before custom code.
- Prefer existing AuthClaw domains and libraries: FastAPI, OPA/Rego, LangGraph, Presidio, SQLAlchemy, Next.js.
- Consider LiteLLM for future provider abstraction only after an audit and explicit approval.
- Keep public APIs, schemas, security behavior, audit behavior, tenant isolation, and policy semantics unchanged unless explicitly requested.

## LOC Discipline
- Make the smallest behavior-preserving change.
- Do not add files unless a clear owner/domain requires them.
- Avoid giant single-use helpers, wrapper-over-wrapper services, and pass-through abstractions.
- Keep comments/docstrings short; explain only non-obvious security or architectural intent.
- Do not add config flags unless required by behavior, compatibility, or deployment.
- Stop and propose a smaller plan if a change exceeds the line budget.

## Review Budgets
- Backend service/module target: <250 LOC; hard review at 400 LOC.
- Backend endpoint target: <300 LOC; hard review at 500 LOC.
- Frontend component target: <300 LOC; hard review at 450 LOC.
- Test file target: <300 LOC; hard review at 500 LOC.
- Any PR with large net-new LOC needs explicit justification.

## LOC Profiles
- Production runtime LOC is `apps/api/app` plus `apps/web/src`; CI gates this at <=60k.
- Product source LOC adds migrations, Docker/config files, package manifests, minimal operational scripts, and CI; CI gates this at <=60k.
- Lockfiles are required for reproducible builds and remain in the product repo, but they are excluded from LOC budgets and reported separately.
- Full development repo LOC includes tests, docs, SDK, infrastructure, and evidence; report-only.
- Tests, docs, and evidence are preserved but excluded from product LOC budgets because they maintain CI confidence, security proof, auditor review, and developer onboarding without shipping in the runtime path.

## Review Checklist
- Reject duplicate logic or reimplemented library features.
- Reject unnecessary files and oversized one-off helpers.
- Reject oversized tests with repeated setup when fixtures can preserve coverage.
- Reject behavior changes hidden inside cleanup/refactor work.

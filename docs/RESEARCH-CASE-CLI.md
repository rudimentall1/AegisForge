# Research Case CLI

The forensic worker roles `source_researcher`, `crypto_analyst`, and `lab_runner` require a registered Research Case. The CLI rejects a submission for these roles when `--case-id` is missing; the worker independently checks the registered case before execution.

## 1. Create a case file

Save a JSON file such as `research-case.json`:

```json
{
  "case_id": "example-evm-case-001",
  "target_repository": "owner/repository",
  "target_commit": "0123456789abcdef0123456789abcdef01234567",
  "scope_url": "https://example.com/security-scope",
  "scope_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "scope_reviewed_on": "2026-10-16",
  "hypothesis": "State the specific behavior that may violate a security invariant.",
  "attacker_capability": "Describe the attacker's permissions and required preconditions.",
  "expected_invariant": "State the property that must remain true.",
  "falsification_criteria": "State what experiment or counterexample would reject the hypothesis.",
  "execution_mode": "local",
  "status": "ready"
}
```

Replace the sample repository, full 40-character commit SHA, scope URL and SHA-256 scope digest with verified values. The digest must represent the exact scope document reviewed; do not use a placeholder in a real case.

Allowed execution modes are `local`, `authorized_fork`, and `testnet`. There is no live-mainnet execution mode.

## 2. Register and inspect the case

```bash
python aegisforge.py tasks case register research-case.json
python aegisforge.py tasks case show example-evm-case-001
```

Use the same SQLite database for registration, task submission, and worker execution. By default, the database is `data/agent_farm.db` relative to the repository root, so a clean checkout does not depend on the server-specific `/opt/agent-farm` path. Set `AEGISFORGE_DB_PATH` to override it for the master and every worker. The CLI's `--db` option is available for isolated local runs and tests.

## 3. Submit a bound forensic task

```bash
python aegisforge.py tasks submit \
  --role crypto_analyst \
  --case-id example-evm-case-001 \
  "Analyze the pinned source and propose a falsifiable local invariant test"
```

A forensic task without `--case-id` is rejected by the CLI. A case ID that is not registered, a mismatched binding, or a case whose status does not permit execution is rejected by queue validation or the worker gate.

Child tasks inherit the parent task's case ID when no explicit case ID is provided.

## Current limitation

Registering a case and submitting a bound task does not by itself prove that the full run-to-evidence workflow is complete. Release acceptance still requires verifying that case identity survives execution, every evidence record and exported artifact, and the portable bundle verifier. CI passing is necessary but is not proof of a security finding.

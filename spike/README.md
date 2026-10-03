# `work <hire>`: one worker for a hired profile

`nano-supervisor work <hire>` is the Rust counterpart of the Node plugin's
`c8 nano work <profile>`. It reads the hire (agent command, protocol, rank,
capabilities, model, env) from the c8ctl-nano `config.json` — the same file
`c8 nano hire` writes — polls the hire's rank×capability job types (plus any
`--job-type`), and runs each job through the job core it shares with
`nano-supervisor daemon` (`src/slot.rs`).

## Run it against a throwaway local cluster

Never point this at a production engine: it takes any job of its job types.

```sh
c8 nano start                                   # local cluster on :8080
c8 nano hire --name dev --rank junior --command nano-coder --arg --acp --protocol acp
curl -F resources=@spike/spike.bpmn localhost:8080/v2/deployments
curl -H 'content-type: application/json' localhost:8080/v2/process-instances \
  -d '{"processDefinitionId":"nano-supervisor-spike","variables":{"prompt":"Reply with exactly SPIKE-OK"}}'

cargo build --release
target/release/nano-supervisor work dev --job-type spike:nano-supervisor --profile local \
  --recovery-window 9000 --max-jobs 1
```

Connection: `--profile` (a c8ctl profile) > `CAMUNDA_REST_ADDRESS` env >
c8ctl's remembered active profile. Durations are in **milliseconds**, as in
c8ctl. An unknown or unrunnable hire exits 78 (`EX_CONFIG`), like Node.

`spike/sample.sh <pid> out.tsv` samples the worker's and its agent's RSS every 0.5 s.

## Behaviour (mirrors the Node plugin)

- **Payload.** The agent is prompted with the JSON job payload (`jobKey`,
  `jobType`, `prompt`, the normalised `task` envelope, `variables`,
  `customHeaders`, `profile`, …) and gets `AGENT_PROFILE`/`AGENT_RANK`/
  `AGENT_MODEL`/`AGENT_CAPABILITIES`/`AGENT_JOB_TYPE`/`AGENT_RESULT_FILE`.
- **Leases.** Every activation asks for a lease (engine 0.0.24 issues
  `jobLeaseToken`, which the SDK carries) and is refreshed every third of
  `--recovery-window`. A 404/409 on refresh is a lost activation: the agent is
  stopped and the job is not settled.
- **Result.** `AGENT_RESULT_FILE`, else the last `::nano:result::` line, else a
  fenced JSON block. With no result but some output, the agent is re-invoked
  once with the re-emit nudge.
- **Complete.** Variables are the result's keys plus `output`, `exitCode`,
  `truncated`, `agent` and the versioned `io.nanobpm.agentResult` envelope.
- **Fail.** An empty result or a failed run fails the job with retries − 1 and
  `agent "<hire>" produced an empty result: …` / `agent "<hire>" failed: …`.
- **Housekeeping.** Run dirs live under `agent-runs/` in the state home and are
  reaped by `--reap-age`/`--reap-interval`; `--keep-runs` keeps them.
  `--min-free-mb` gates container sandboxes only, so host hires are not gated.

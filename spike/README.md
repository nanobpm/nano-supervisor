# Spike: one worker slot on camunda-orchestration-sdk (issue #1)

`nano-supervisor spike` runs a single worker slot: poll one job type, keep the
activation alive while an ACP agent works, complete or fail the job.

## Run it against a throwaway local cluster

Never point this at a production engine: it takes any job of `--job-type`.

```sh
c8 nano start                                   # local cluster on :8080
curl -F resources=@spike/spike.bpmn localhost:8080/v2/deployments
curl -H 'content-type: application/json' localhost:8080/v2/process-instances \
  -d '{"processDefinitionId":"nano-supervisor-spike","variables":{"prompt":"Reply with exactly SPIKE-OK"}}'

cargo build --release
target/release/nano-supervisor spike --job-type spike:nano-supervisor --profile local \
  --agent "nano-coder --acp" --recovery-window 9000 --max-jobs 1
```

Connection: `--profile` (a c8ctl profile) > `CAMUNDA_REST_ADDRESS` env >
c8ctl's remembered active profile.

`spike/sample.sh <pid> out.tsv` samples the worker's and its agent's RSS every 0.5 s.

## What it does and doesn't do

- Activates with `timeout = --recovery-window` and extends it every third of the
  window (`update_job`). A 404/409 on refresh counts as a lost activation: the agent
  is stopped and the job is not settled.
- Passes a `jobLeaseToken` through if the engine issues one (`--with-lease` asks for
  it; current Nano engines don't issue tokens).
- Fails the job (retries − 1) on any error, including an agent that finishes with
  no output.
- No git, no result file / `::nano:result::`, no hub, no sandbox: those are
  the port, not the spike.

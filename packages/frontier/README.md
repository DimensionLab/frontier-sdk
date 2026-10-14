# frontier

Python SDK for Frontier: log the metrics, artifacts and summary of a training run to disk
and to a Frontier server.

## Install

Install the wheel from the release bundle:

```bash
pip install --no-index --find-links wheels frontier
```

## Example

```python
import frontier

run = frontier.init(project="my-project", name="my-run", config={"lr": 1e-3})
for step in range(1000):
    run.log({"train/loss": 0.1, "cfd/cd_rel_err": 0.02}, step=step)
run.log_artifact("runs/my-run/best.pt", name="best.pt")
run.summary["val/cd/r2"] = 0.96
run.finish()  # or: with frontier.init(...) as run: ...
```

## Where runs go

Every run is written under `.frontier/<project>/`. Change the directory with `FRONTIER_DIR`
or `directory=`.

| File                        | Contents                                                    |
| --------------------------- | ----------------------------------------------------------- |
| `<run_id>.run.json`         | Config, state (`running`, `finished`, `failed`) and summary |
| `<run_id>.metrics.jsonl`    | One line of metrics per logged step                         |
| `<run_id>/artifacts/<name>` | Copies of the files passed to `log_artifact`                |

To also send a run to a server, pass `server="https://frontier.example.com"` to
`frontier.init` or set `FRONTIER_SERVER`. `FRONTIER_TOKEN` is sent as a bearer token when
set. If the server cannot be reached, the run logs one warning and continues on disk.

## API

| Name                                                       | What it does                                               |
| ---------------------------------------------------------- | ---------------------------------------------------------- |
| `frontier.init(...)`                                       | Start a run and return a `Run`                             |
| `Run.log`, `Run.log_artifact`, `Run.summary`, `Run.finish` | Record metrics, files and final values, then close the run |
| `frontier.ServerClient`                                    | Call the server API ([spec](../../docs/spec/api.md))       |
| `frontier.config`                                          | Read Frontier settings                                     |
| `frontier.auth`                                            | Read stored credentials                                    |

## Licence

Apache-2.0.

## Documentation

- [Server API](../../docs/spec/api.md)

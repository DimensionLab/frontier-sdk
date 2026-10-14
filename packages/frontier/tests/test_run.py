# SPDX-License-Identifier: Apache-2.0

import json

import frontier


def test_init_and_log_writes_jsonl(tmp_path):
    with frontier.init(project="p", name="n", config={"lr": 1e-3}, directory=tmp_path) as run:
        run.log({"loss": 1.0})
        run.log({"loss": 0.5, "cfd/cd_rel_err": 0.1}, step=10)
        run.log({"loss": 0.25})

    files = sorted((tmp_path / "p").glob("*.metrics.jsonl"))
    assert len(files) == 1
    lines = [json.loads(line) for line in files[0].read_text().splitlines()]
    assert [line["step"] for line in lines] == [0, 10, 11]
    assert (tmp_path / "p" / f"{run.id}.run.json").exists()


def test_non_finite_values_never_break_finish(tmp_path):
    import math

    from frontier._run import _json_safe

    assert _json_safe({"a": float("nan"), "b": [float("inf"), 1.5]}) == {
        "a": None,
        "b": [None, 1.5],
    }
    with frontier.init(project="p", name="nan", directory=tmp_path) as run:
        run.log({"val/cd/r2": float("nan"), "train/loss": 0.5})
        run.summary["best"] = {"val/cd/r2": float("nan")}
    meta = json.loads((tmp_path / "p" / f"{run.id}.run.json").read_text())
    assert meta["summary"]["best"]["val/cd/r2"] is None
    assert math.isfinite(0.5)

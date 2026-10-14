# SPDX-License-Identifier: Apache-2.0
"""A failure the user can act on ends in one line; a defect keeps its traceback."""

from __future__ import annotations

import pytest

from frontier import cli_errors
from frontier.config import OfflineError


def test_expected_errors_are_one_line(capsys, monkeypatch) -> None:
    def missing() -> None:
        open("/no/such/dir/file.pt")  # noqa: PTH123, SIM115

    with pytest.raises(SystemExit) as exit_info:
        cli_errors.run(missing)
    assert exit_info.value.code == 2
    assert capsys.readouterr().err == "error: No such file or directory: /no/such/dir/file.pt\n"

    def refused() -> None:
        raise OfflineError("offline: downloads are disabled")

    with pytest.raises(SystemExit) as exit_info:
        cli_errors.run(refused, code=1)
    assert exit_info.value.code == 1
    assert capsys.readouterr().err == "error: offline: downloads are disabled\n"

    def defect() -> None:
        raise ZeroDivisionError("a bug")

    with pytest.raises(ZeroDivisionError):
        cli_errors.run(defect)
    monkeypatch.setenv("FRONTIER_TRACEBACK", "1")
    with pytest.raises(OfflineError):
        cli_errors.run(refused)


def test_status_of_the_entry_is_the_exit_status() -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli_errors.run(lambda: 3)
    assert exit_info.value.code == 3
    with pytest.raises(SystemExit) as exit_info:
        cli_errors.run(lambda: None)
    assert exit_info.value.code == 0
    assert cli_errors.message(KeyError("unknown model 'x'")) == "unknown model 'x'"

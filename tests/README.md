# Tests

Run `python -m unittest discover -s tests -v` from the project root after installing `requirements-cli.txt`.

The suite uses synthetic reports and mocked network probes. It does not contact DNS providers or target servers, and does not require a display or GUI dependencies.

Deadline tests use real spawned processes with intentionally stalled probes. They verify that snapshots survive, workers are terminated, reader threads exit, and the same supervisor works from a GUI-style background thread.

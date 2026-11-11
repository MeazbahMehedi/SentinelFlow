"""Print capture prerequisites and friendly interface details without starting capture."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinelflow.capture import capture_diagnostics  # noqa: E402

print(json.dumps(capture_diagnostics(refresh=True), indent=2))

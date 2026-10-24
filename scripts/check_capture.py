"""Print capture prerequisites and friendly interface details without starting capture."""
from pathlib import Path
import sys,json
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sentinelflow.capture import capture_diagnostics
print(json.dumps(capture_diagnostics(refresh=True),indent=2))

"""Check detector coverage on bundled fixtures. Not a real-world accuracy benchmark."""
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sentinelflow.packets import read_capture
from sentinelflow.detection import Detector
from sentinelflow.db import DEFAULT_RULES,DEFAULT_SETTINGS

root=Path(__file__).resolve().parents[1]
report={}
for filename in ['guided-threats.pcap','normal-traffic.pcap']:
    events=read_capture(root/'samples'/filename)
    detector=Detector(DEFAULT_RULES,DEFAULT_SETTINGS)
    hits=[a for e in events for a in detector.observe(e)]
    report[filename]={'packets':len(events),'alerts':len(hits),'rules':sorted({a['rule'] for a in hits})}
report['scope']='Deterministic synthetic fixture coverage only; no claim about real-world precision or recall.'
print(json.dumps(report,indent=2))
assert report['guided-threats.pcap']['rules']==sorted(DEFAULT_RULES)
assert report['normal-traffic.pcap']['alerts']==0

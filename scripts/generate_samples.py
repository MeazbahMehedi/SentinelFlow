"""Generate safe synthetic capture files. This script never sends packets."""
import json
from pathlib import Path
import sys
import dpkt
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sentinelflow.packets import make_demo,make_packet


def generate():
    root=Path(__file__).resolve().parents[1]/'samples'
    root.mkdir(exist_ok=True)
    make_demo(root/'guided-threats.pcap')
    with (root/'normal-traffic.pcap').open('wb') as f:
        writer=dpkt.pcap.Writer(f)
        for i in range(60):
            writer.writepkt(make_packet(f'10.0.0.{10+i%4}','198.51.100.20',sport=40000+i,payload=b'normal traffic'),1760000000+i*.5)
    eve={'timestamp':'2025-10-09T08:53:49+00:00','event_type':'alert','src_ip':'10.0.0.50','dest_ip':'203.0.113.66','alert':{'signature':'Synthetic example signature for import testing','category':'Demonstration only','severity':2,'signature_id':1000001}}
    (root/'example-eve.json').write_text(json.dumps(eve)+'\n')
    print('Created guided-threats.pcap (501 packets), normal-traffic.pcap (60 packets), and example-eve.json.')

if __name__=='__main__':generate()

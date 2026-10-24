"""Import an existing Suricata EVE JSON alert file; does not run Suricata."""
from datetime import datetime
import ipaddress
import json
import math
import time


def read_eve(path):
    alerts=[]
    lines=0
    with open(path,'r',encoding='utf-8-sig') as f:
        for line in f:
            lines+=1
            if lines>50000:
                raise ValueError('EVE import is limited to 50,000 lines.')
            if len(line)>1000000:
                raise ValueError('EVE lines must be below 1 MB.')
            if not line.strip():
                continue
            try:
                event=json.loads(line)
                if not isinstance(event,dict):
                    raise ValueError('Each EVE line must be a JSON object.')
                if event.get('event_type')!='alert':
                    continue
                detail=event['alert']
                ts=datetime.fromisoformat(event['timestamp'].replace('Z','+00:00'))
                if ts.tzinfo is None:
                    raise ValueError('EVE timestamps must include a timezone.')
                timestamp=ts.timestamp()
                if not math.isfinite(timestamp) or not 0<=timestamp<=253402300799:
                    raise ValueError('Invalid timestamp.')
                severity={1:'high',2:'medium',3:'low'}.get(int(detail.get('severity',3)),'low')
                alerts.append(dict(ts=timestamp,rule='suricata_signature',severity=severity,
                    src=str(ipaddress.ip_address(event['src_ip'])),dst=str(ipaddress.ip_address(event['dest_ip'])),
                    title=str(detail['signature'])[:200],evidence={
                    'observed':1,'threshold':1,'window_seconds':0,'description':str(detail.get('category','Suricata signature alert'))[:500],
                    'signature_id':str(detail.get('signature_id',''))[:50],'event_time':timestamp,
                    'note':'Imported Suricata signature alert. Confirm sensor placement, rule configuration, and supporting evidence.'}))
            except (KeyError,TypeError,ValueError,OverflowError) as exc:
                raise ValueError(f'Invalid EVE record on line {lines}. Use newline-delimited Suricata EVE JSON with timezone timestamps.') from exc
    if not alerts:
        raise ValueError('No Suricata alert events were found in this file.')
    return alerts


def import_eve(store,name,alerts):
    with store.connect() as c:
        sid=c.execute("INSERT INTO sessions(name,source,status,created) VALUES(?,'suricata','finished',?)",(name,time.time())).lastrowid
        for a in alerts:
            c.execute('INSERT INTO alerts(session_id,ts,rule,severity,src,dst,title,evidence) VALUES(?,?,?,?,?,?,?,?)',
                (sid,a['ts'],a['rule'],a['severity'],a['src'],a['dst'],a['title'],json.dumps(a['evidence'])))
    store.audit('eve_import',f'{len(alerts)} alerts in session {sid}')
    return sid

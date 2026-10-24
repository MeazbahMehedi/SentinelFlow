import json
import time
from sentinelflow.detection import Detector
from sentinelflow.db import Store,DEFAULT_RULES,DEFAULT_SETTINGS
from sentinelflow.engine import Engine
from sentinelflow.packets import normalize_bytes,make_packet
import pytest


def events():
    return [normalize_bytes(make_packet('10.0.0.1','10.0.0.2',dport=30+i,flags=2),100+i*.01) for i in range(15)]

@pytest.mark.parametrize('speed',[1,4,32])
def test_replay_speed_invariance(app,speed):
    engine=app.extensions['engine'];store=app.extensions['store']
    sid=engine.import_events('sample',events())
    engine.start_replay(sid,speed);engine.worker.join(5)
    assert store.one('SELECT COUNT(*) n FROM packets')['n']==15
    alerts=store.rows('SELECT * FROM alerts')
    assert len(alerts)==1 and json.loads(alerts[0]['evidence'])['observed']==12


def test_pause_resume_and_busy(app):
    engine=app.extensions['engine'];store=app.extensions['store']
    ev=events();ev[-1]['ts']=110
    sid=engine.import_events('sample',ev);engine.start_replay(sid,1)
    engine.control(sid,'pause');time.sleep(.1)
    assert store.one('SELECT status FROM sessions')['status']=='paused'
    with pytest.raises(ValueError):engine.start_replay(sid,1)
    engine.control(sid,'resume');engine.control(sid,'stop');engine.worker.join(3)
    assert store.one('SELECT status FROM sessions')['status']=='stopped'


def test_restart_replaces_results(app):
    e=app.extensions['engine'];s=app.extensions['store'];sid=e.import_events('sample',events())
    for _ in range(2):e.start_replay(sid,32);e.worker.join(5)
    assert s.one('SELECT COUNT(*) n FROM packets')['n']==15
    assert s.one('SELECT COUNT(*) n FROM alerts')['n']==1


def test_frozen_rules(app):
    e=app.extensions['engine'];s=app.extensions['store'];sid=e.import_events('sample',events())
    e.start_replay(sid,1)
    rules=s.config('rules');rules['port_scan']['enabled']=False;s.set_config('rules',rules)
    e.worker.join(5)
    assert s.one('SELECT COUNT(*) n FROM alerts')['n']==1


def test_restart_marks_interrupted(app):
    s=app.extensions['store'];sid=s.execute("INSERT INTO sessions(name,source,status,created) VALUES('old','pcap','running',0)")
    other=Store(s.path)
    assert other.one('SELECT status FROM sessions WHERE id=?',(sid,))['status']=='interrupted'


def test_delete_cascade(client,token,app):
    e=app.extensions['engine'];s=app.extensions['store'];sid=e.import_events('sample',events());e.start_replay(sid,32);e.worker.join(5)
    client.post(f'/sessions/{sid}/delete',data={'csrf_token':token})
    for table in ['packets','alerts','replay_packets','sessions']:
        assert s.one('SELECT COUNT(*) n FROM '+table)['n']==0

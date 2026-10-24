import io,json
import pytest
from sentinelflow.integrations import read_eve

EVENT={'timestamp':'2026-01-01T12:00:00+00:00','event_type':'alert','src_ip':'10.0.0.1','dest_ip':'203.0.113.66','alert':{'signature':'Example signature','category':'Test traffic','severity':2,'signature_id':1001}}

def test_eve_import(client,token,app):
    data=(json.dumps({'event_type':'flow'})+'\n'+json.dumps(EVENT)+'\n').encode()
    r=client.post('/replay/eve',data={'csrf_token':token,'eve':(io.BytesIO(data),'eve.json')},follow_redirects=True)
    assert r.status_code==200
    alert=app.extensions['store'].one('SELECT * FROM alerts')
    assert alert['rule']=='suricata_signature' and alert['severity']=='medium'
    assert client.get('/alerts/'+str(alert['id'])).status_code==200
    assert client.get('/analytics').status_code==200
    assert client.get('/replay').status_code==200

@pytest.mark.parametrize('data',['not json','[]','{"event_type":"flow"}',json.dumps({**EVENT,'timestamp':'not a date'})])
def test_eve_bad_lines(tmp_path,data):
    p=tmp_path/'eve.json';p.write_text(data)
    with pytest.raises(ValueError):read_eve(p)

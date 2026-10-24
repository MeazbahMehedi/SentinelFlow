import io
import json
import time
from PIL import Image
import pytest
from sentinelflow.db import DEFAULT_RULES
from sentinelflow.packets import make_packet,normalize_bytes

@pytest.mark.parametrize('path',['/','/traffic','/alerts','/replay','/hosts','/analytics','/rules','/team','/settings','/team/1/edit','/repositories','/api/snapshot','/api/packets','/export/summary','/export/packets','/export/alerts'])
def test_pages(client,path):
    assert client.get(path).status_code==200


def test_login_required(app):
    c=app.test_client();c.get('/setup')
    with c.session_transaction() as s:t=s['csrf']
    c.post('/setup',data={'csrf_token':t,'username':'analyst','email':'analyst@gmail.com','password':'long-password-123'})
    with c.session_transaction() as s:s.clear()
    assert c.get('/').status_code==302
    assert c.get('/api/snapshot').status_code==401


def test_csrf_rejected(client):
    assert client.post('/replay/demo').status_code==400


def test_demo_and_start(client,token,app):
    r=client.post('/replay/demo',data={'csrf_token':token},follow_redirects=True)
    assert r.status_code==200
    row=app.extensions['store'].one('SELECT * FROM sessions')
    assert row['source']=='demo' and row['total']==501
    r=client.post(f"/sessions/{row['id']}/start",data={'csrf_token':token,'speed':'32'})
    assert r.status_code==302
    app.extensions['engine'].worker.join(timeout=15)
    summary=client.get('/api/snapshot').json
    assert summary['totals']['packets']==501
    assert summary['totals']['alerts']==6
    assert summary['sessions'][0]['status']=='finished'
    assert client.get('/traffic?session=1&q=10.0.0.45').status_code==200
    assert client.get('/alerts/1').status_code==200
    assert client.get('/hosts/10.0.0.45').status_code==200
    assert client.post('/alerts/1',data={'csrf_token':token,'status':'resolved','note':'Reviewed'}).status_code==302
    assert app.extensions['store'].one('SELECT status FROM alerts WHERE id=1')['status']=='resolved'


def test_bad_upload(client,token):
    r=client.post('/replay/upload',data={'csrf_token':token,'capture':(io.BytesIO(b'not pcap'),'bad.pcap')},follow_redirects=True)
    assert r.status_code==200 and b'Unable to parse' in r.data


def test_session_filter_validation(client):
    assert client.get('/api/snapshot?session=abc').status_code==400
    assert client.get('/api/snapshot?session=999').status_code==404


def test_profile_links_validated(client,token):
    r=client.post('/team/1/edit',data={'csrf_token':token,'name':'Student','website':'javascript:alert(1)'},follow_redirects=True)
    assert b'HTTP or HTTPS' in r.data


def test_profile_photo_and_cv(client,token,app):
    b=io.BytesIO();Image.new('RGB',(30,30),'green').save(b,format='PNG');b.seek(0)
    r=client.post('/team/1/edit',data={'csrf_token':token,'name':'Student A','bio':'<script>alert(1)</script>','photo':(b,'me.png'),'cv':(io.BytesIO(b'%PDF-1.4\n%%EOF'),'cv.pdf')},follow_redirects=True)
    assert r.status_code==200 and b'&lt;script&gt;' in r.data
    p=app.extensions['store'].one('SELECT * FROM profiles WHERE id=1')
    assert p['photo'].endswith('.png') and p['cv'].endswith('.pdf')
    assert client.get('/media/'+p['photo']).status_code==200
    assert 'attachment' in client.get('/media/'+p['cv']).headers['Content-Disposition']


def test_invalid_cv_rejected(client,token,app):
    client.post('/team/1/edit',data={'csrf_token':token,'name':'Student','cv':(io.BytesIO(b'<html>bad</html>'),'bad.pdf')})
    assert not app.extensions['store'].one('SELECT * FROM profiles WHERE id=1')['cv']


def test_rules_validate_transaction(client,token,app):
    original=app.extensions['store'].config('rules')
    client.post('/rules',data={'csrf_token':token})
    assert app.extensions['store'].config('rules')==original


def test_settings_validation(client,token,app):
    previous=app.extensions['store'].config('settings')
    client.post('/settings',data={'csrf_token':token,'indicators':'not_an_ip','local_networks':'10.0.0.0/8','max_packets':100000})
    assert app.extensions['store'].config('settings')==previous


def test_headers(client):
    headers=client.get('/').headers
    assert headers['X-Content-Type-Options']=='nosniff'
    assert "script-src 'self'" in headers['Content-Security-Policy']


def test_export_csv_formula_escape(client,token,app):
    engine=app.extensions['engine'];store=app.extensions['store']
    e=normalize_bytes(make_packet('10.0.0.1','203.0.113.66'),100)
    sid=engine.import_events('test',[e]);engine.start_replay(sid,32);engine.worker.join(5)
    store.execute('UPDATE alerts SET note=?',('=SUM(1,2)',))
    assert "'=SUM" in client.get('/export/alerts').text


def test_live_permission_error_handled(client,token,monkeypatch,app):
    def fail(_):raise PermissionError('Capture permission denied')
    monkeypatch.setattr(app.extensions['engine'],'start_live',fail)
    r=client.post('/live/start',data={'csrf_token':token,'interface':'eth0'},follow_redirects=True)
    assert r.status_code==200 and b'Capture could not start' in r.data


def test_stream_first_event(client):
    response=client.get('/api/stream',buffered=False)
    first=next(response.response).decode()
    assert first.startswith('data: ')
    assert json.loads(first[6:])['totals']['packets']==0
    response.close()


def test_invalid_speed(client,token):
    r=client.post('/sessions/1/start',data={'csrf_token':token,'speed':'nan'})
    assert r.status_code==302


def test_password_change(client,token,app):
    client.post('/settings/password',data={'csrf_token':token,'current_password':'test-password-12345','new_password':'new-password-12345'})
    from werkzeug.security import check_password_hash
    assert check_password_hash(app.extensions['store'].one('SELECT * FROM users')['password'],'new-password-12345')

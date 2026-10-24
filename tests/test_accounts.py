import json
import sqlite3
import pytest
from werkzeug.security import generate_password_hash
from sentinelflow import create_app
from sentinelflow.accounts import canonical_gmail
from sentinelflow.packets import make_packet,normalize_bytes

@pytest.mark.parametrize('address',['analyst@gmail.com','AN.ALYST@gmail.com','analyst+class@gmail.com','an.alyst+one@googlemail.com',' analyst@gmail.com '])
def test_gmail_aliases(address):
    assert canonical_gmail(address)=='analyst@gmail.com'

@pytest.mark.parametrize('address',['student@example.com','bad@@gmail.com','@gmail.com','a..b@gmail.com','a@gmail.com.evil.test','a+@gmail.com','<a>@gmail.com'])
def test_non_gmail_invalid(address):
    with pytest.raises(ValueError):canonical_gmail(address)


def csrf(client):
    client.get('/')
    with client.session_transaction() as session:return session['csrf']


def second_account(app):
    c=app.test_client();c.get('/register')
    with c.session_transaction() as s:t=s['csrf']
    r=c.post('/register',data={'csrf_token':t,'username':'second','email':'second@gmail.com','password':'second-password-12345'})
    assert r.status_code==302
    return c


def test_one_gmail_once(client,token,app):
    c=app.test_client();c.get('/register')
    with c.session_transaction() as s:t=s['csrf']
    r=c.post('/register',data={'csrf_token':t,'username':'duplicate','email':'an.alyst+new@gmail.com','password':'another-password-12345'},follow_redirects=True)
    assert b'already has an account' in r.data
    assert app.extensions['identities'].one('SELECT COUNT(*) n FROM users')['n']==1


def test_username_case_unique(client,token,app):
    r=client.post('/register',data={'csrf_token':token,'username':'ANALYST','email':'other@gmail.com','password':'another-password-12345'},follow_redirects=True)
    assert b'username is already in use' in r.data


def test_account_isolation_all_views(client,app):
    engine=app.extensions['engine'];main=app.extensions['store']
    event=normalize_bytes(make_packet('10.4.3.2','203.0.113.66'),100)
    sid=engine.import_events('Private admin investigation',[event]);engine.start_replay(sid,32);engine.worker.join(3)
    second=second_account(app)
    snap=second.get('/api/snapshot').json
    assert snap['sessions']==[] and snap['totals']['packets']==0 and snap['totals']['alerts']==0
    assert second.get('/api/packets').json==[]
    assert second.get('/alerts/1').status_code==404
    assert second.get('/api/snapshot?session=1').status_code==404
    assert '10.4.3.2' not in second.get('/export/packets').text
    assert second.post('/alerts/1',data={'csrf_token':csrf(second),'status':'resolved'}).status_code==404
    second.post('/sessions/1/delete',data={'csrf_token':csrf(second)})
    assert main.one('SELECT COUNT(*) n FROM sessions')['n']==1
    assert main.one('SELECT status FROM alerts')['status']=='new'
    stream=second.get('/api/stream',buffered=False)
    assert json.loads(next(stream.response).decode()[6:])['totals']['packets']==0
    stream.close()


def test_private_rules_and_capture_progress(client,app):
    second=second_account(app)
    second.get('/')
    with second.session_transaction() as s:uid=s['uid']
    private,engine=app.extensions['workspace_for'](uid)
    rules=private.config('rules');rules['port_scan']['threshold']=99;private.set_config('rules',rules)
    assert app.extensions['store'].config('rules')['port_scan']['threshold']==12
    sid=engine.import_events('Second account capture',[normalize_bytes(make_packet('10.8.8.8','10.8.8.9'),100)])
    engine.start_replay(sid,32);engine.worker.join(3)
    assert second.get('/api/snapshot').json['totals']['packets']==1
    assert client.get('/api/snapshot').json['totals']['packets']==0


def test_analyst_cannot_edit_global_profiles(client,app):
    c=second_account(app)
    assert c.get('/team/1/edit').status_code==403
    assert c.post('/team/1/edit',data={'csrf_token':csrf(c),'name':'Hijack'}).status_code==403
    assert app.extensions['identities'].one('SELECT name FROM profiles WHERE id=1')['name']=='Your name'
    assert b'Edit profile' not in c.get('/team').data


def test_sign_in_gmail_alias(client,token,app):
    client.post('/logout',data={'csrf_token':token});client.get('/login')
    with client.session_transaction() as s:t=s['csrf']
    r=client.post('/login',data={'csrf_token':t,'username':'AN.ALYST+tag@googlemail.com','password':'test-password-12345'})
    assert r.status_code==302
    with client.session_transaction() as s:assert s['uid']==1


def test_legacy_account_migration_and_linking(tmp_path):
    directory=tmp_path/'legacy';directory.mkdir()
    db=directory/'sentinelflow.db'
    with sqlite3.connect(db) as c:
        c.execute('CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,password TEXT NOT NULL)')
        c.execute('INSERT INTO users VALUES(1,?,?)',('legacy',generate_password_hash('legacy-password-12345')))
    app=create_app({'TESTING':True,'DATA_DIR':directory})
    try:
        user=app.extensions['identities'].one('SELECT * FROM users')
        assert user['role']=='admin' and user['email'] is None
        c=app.test_client();c.get('/login')
        with c.session_transaction() as s:t=s['csrf']
        c.post('/login',data={'csrf_token':t,'username':'legacy','password':'legacy-password-12345'})
        c.post('/account/email',data={'csrf_token':csrf(c),'email':'leg.acy+course@gmail.com','password':'legacy-password-12345'})
        assert app.extensions['identities'].one('SELECT email FROM users')['email']=='legacy@gmail.com'
    finally:app.extensions['shutdown']()


def test_only_admin_can_capture_and_manage_roles(client,token,app):
    second=second_account(app)
    assert second.get('/api/capture/status').status_code==403
    assert second.post('/live/start',data={'csrf_token':csrf(second),'interface':'eth0'}).status_code==403
    assert second.post('/accounts/1/role',data={'csrf_token':csrf(second),'role':'analyst'}).status_code==403
    assert client.post('/accounts/1/role',data={'csrf_token':token,'role':'analyst'}).status_code==400
    assert client.post('/accounts/2/role',data={'csrf_token':token,'role':'admin'}).status_code==302
    assert app.extensions['identities'].one('SELECT role FROM users WHERE id=2')['role']=='admin'
    assert second.get('/team/1/edit').status_code==200

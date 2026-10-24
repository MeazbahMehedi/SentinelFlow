import re
import pytest
from sentinelflow import create_app

@pytest.fixture
def app(tmp_path):
    app=create_app({'TESTING':True,'DATA_DIR':tmp_path,'SECRET_KEY':'test-only-secret'})
    yield app
    app.extensions['shutdown']()

@pytest.fixture
def client(app):
    c=app.test_client()
    c.get('/setup')
    with c.session_transaction() as sess:
        token=sess['csrf']
    c.post('/setup',data={'csrf_token':token,'username':'analyst','email':'analyst@gmail.com','password':'test-password-12345'})
    return c

@pytest.fixture
def token(client):
    client.get('/')
    with client.session_transaction() as sess:
        return sess['csrf']

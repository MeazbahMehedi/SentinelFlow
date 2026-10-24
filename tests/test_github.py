import io,json
from urllib.error import HTTPError,URLError
import pytest
import sentinelflow.github as github

PROFILE={'login':'MeazbahMehedi','name':'Meazbah Mehedi','avatar_url':'https://avatars.githubusercontent.com/u/123?v=4','bio':'Developer','followers':4,'following':2,'public_repos':101,'location':'Dhaka','company':None,'blog':'https://example.com','created_at':'2020-01-01T00:00:00Z'}

REPO={'name':'Example','html_url':'https://github.com/MeazbahMehedi/Example','description':'<script>text</script>','language':'Python','stargazers_count':2,'forks_count':0,'updated_at':'2026-10-24T00:00:00Z','topics':['security'],'private':False}


def test_public_fetch_and_cache(tmp_path,monkeypatch):
    calls=[]
    def fetch(request,timeout):
        calls.append(request.full_url)
        return io.BytesIO(json.dumps([REPO] if '/repos?' in request.full_url else PROFILE).encode())
    monkeypatch.setattr(github,'urlopen',fetch)
    service=github.GitHubProjects(tmp_path)
    one=service.repositories('MeazbahMehedi');two=service.repositories('MeazbahMehedi')
    assert one['state']=='live' and two['state']=='cached'
    assert one['repos'][0]['name']=='Example' and len(calls)==2
    assert one['profile']['name']=='Meazbah Mehedi' and two['profile']['state']=='cached'


def test_github_offline_no_fake_repos(tmp_path,monkeypatch):
    def fail(*args,**kwargs):raise URLError('Offline')
    monkeypatch.setattr(github,'urlopen',fail)
    service=github.GitHubProjects(tmp_path);result=service.repositories('ItsMONIKAAKTER')
    assert result['state']=='unavailable' and result['repos']==[]


def test_stale_cache_and_rate_limit(tmp_path,monkeypatch):
    cached={'repos':[{'name':'Old'}],'fetched_at':1}
    (tmp_path/'MeazbahMehedi.json').write_text(json.dumps(cached))
    calls=[]
    def fail(*args,**kwargs):
        calls.append(1);raise HTTPError('https://api.github.com',429,'Rate limited',{'Retry-After':'120'},None)
    monkeypatch.setattr(github,'urlopen',fail)
    service=github.GitHubProjects(tmp_path)
    first=service.repositories('MeazbahMehedi');second=service.repositories('MeazbahMehedi')
    assert first['state']==second['state']=='stale' and first['repos'][0]['name']=='Old'
    assert len(calls)==2


def test_github_unknown_owner(tmp_path):
    with pytest.raises(ValueError):github.GitHubProjects(tmp_path).repositories('not-configured')


def test_api_owner_allowlist(client):
    assert client.get('/api/github/unknown').status_code==404


def test_multiple_repository_pages_and_profile(tmp_path,monkeypatch):
    calls=[]
    def fetch(request,timeout):
        calls.append(request.full_url)
        data=PROFILE
        if '/repos?' in request.full_url:
            start,end=(0,100) if request.full_url.endswith('&page=1') else (100,101)
            data=[dict(REPO,name=f'Project{i}',html_url=f'https://github.com/MeazbahMehedi/Project{i}') for i in range(start,end)]
        return io.BytesIO(json.dumps(data).encode())
    monkeypatch.setattr(github,'urlopen',fetch)
    result=github.GitHubProjects(tmp_path).repositories('MeazbahMehedi')
    assert len(result['repos'])==101 and not result['truncated']
    assert result['repos'][-1]['name']=='Project100'
    assert result['profile']['followers']==4 and len(calls)==3


@pytest.mark.parametrize('avatar,website',[
    ('javascript:alert(1)','javascript:alert(2)'),
    ('https://avatars.githubusercontent.com.evil.test/u/1','http://example.com'),
    ('https://evil.test/avatar','https://user:password@example.com'),
])
def test_profile_rejects_unsafe_urls(tmp_path,monkeypatch,avatar,website):
    monkeypatch.setattr(github,'urlopen',lambda *a,**k:io.BytesIO(json.dumps(dict(PROFILE,avatar_url=avatar,blog=website)).encode()))
    result=github.GitHubProjects(tmp_path).profile('MeazbahMehedi')
    assert result['state']=='live' and not result['avatar_url'] and not result['website']


def test_profile_failure_does_not_hide_repositories(tmp_path,monkeypatch):
    def fetch(request,timeout):
        if '/repos?' not in request.full_url:raise URLError('Profile unavailable')
        return io.BytesIO(json.dumps([REPO]).encode())
    monkeypatch.setattr(github,'urlopen',fetch)
    result=github.GitHubProjects(tmp_path).repositories('MeazbahMehedi')
    assert result['state']=='live' and len(result['repos'])==1
    assert result['profile']['state']=='unavailable' and result['profile']['followers'] is None


def test_repositories_failure_does_not_hide_profile(tmp_path,monkeypatch):
    def fetch(request,timeout):
        if '/repos?' in request.full_url:raise URLError('Repos unavailable')
        return io.BytesIO(json.dumps(PROFILE).encode())
    monkeypatch.setattr(github,'urlopen',fetch)
    result=github.GitHubProjects(tmp_path).repositories('MeazbahMehedi')
    assert result['state']=='unavailable' and result['profile']['name']=='Meazbah Mehedi'


def test_stale_profile_retains_avatar_and_name(tmp_path,monkeypatch):
    service=github.GitHubProjects(tmp_path)
    monkeypatch.setattr(github,'urlopen',lambda *a,**k:io.BytesIO(json.dumps(PROFILE).encode()))
    live=service.profile('MeazbahMehedi')
    cached=dict(live,fetched_at=1)
    (tmp_path/'MeazbahMehedi.profile.json').write_text(json.dumps(cached))
    def fail(*a,**k):raise URLError('Offline')
    monkeypatch.setattr(github,'urlopen',fail)
    stale=service.profile('MeazbahMehedi')
    assert stale['state']=='stale' and stale['avatar_url']==PROFILE['avatar_url']


def test_fixed_accounts_read_only_and_independent_of_team(client,app,token,monkeypatch):
    app.extensions['store'].execute("UPDATE profiles SET github='https://github.com/other',name='Local name'")
    page=client.get('/repositories')
    assert page.status_code==200
    assert b'data-github-account="MeazbahMehedi"' in page.data
    assert b'data-github-account="ItsMONIKAAKTER"' in page.data
    assert b'data-github-account="other"' not in page.data
    assert b'data-profile-name' in page.data and b'data-github-avatar' in page.data
    monkeypatch.setattr(github,'urlopen',lambda *a,**k:io.BytesIO(json.dumps([] if '/repos?' in a[0].full_url else PROFILE).encode()))
    assert client.post('/api/github/MeazbahMehedi',data={'csrf_token':token,'login':'other'}).status_code==405
    assert client.post('/repositories',data={'csrf_token':token,'login':'other'}).status_code==405
    assert 'https://avatars.githubusercontent.com' in page.headers['Content-Security-Policy']

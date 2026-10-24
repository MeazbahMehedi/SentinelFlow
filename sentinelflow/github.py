"""Read-only, fixed-owner GitHub profiles and public repositories."""
import json
import threading
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

# Deliberately code-owned: neither settings nor developer-profile edits change these.
DEVELOPERS = ('MeazbahMehedi', 'ItsMONIKAAKTER')


def _web_url(value, host=None):
    value = str(value or '')[:1000]
    try:
        parsed = urlsplit(value)
        if parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password:
            if host is None or parsed.netloc == host:
                return value
    except ValueError:
        pass
    return ''


def _number(value):
    return max(0, int(value or 0))


class GitHubProjects:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(exist_ok=True)
        self.locks = {(name, kind): threading.Lock() for name in DEVELOPERS for kind in ('repos', 'profile')}
        self.retry_after = {}

    @staticmethod
    def _request(url):
        request = Request(url, headers={'User-Agent': 'SentinelFlow/1.1.1',
                          'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
        with urlopen(request, timeout=6) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('GitHub response exceeded the safe size limit.')
        return json.loads(raw)

    def _cached(self, login, kind, fetch, default):
        if login not in DEVELOPERS:
            raise ValueError('Unknown project developer.')
        key = (login, kind)
        path = self.directory / (login + ('.json' if kind == 'repos' else '.profile.json'))
        with self.locks[key]:
            cached = None
            try:
                cached = json.loads(path.read_text(encoding='utf-8'))
                if not isinstance(cached, dict) or not isinstance(cached.get('fetched_at'), (int, float)):
                    cached = None
            except (OSError, ValueError):
                pass
            now = time.time()
            base = dict(default, login=login, profile_url='https://github.com/' + login,
                        fetched_at=None, state='unavailable', message='')
            if cached:
                base.update(cached)
                # Identity always comes from the code-owned allowlist.
                base.update(login=login, profile_url='https://github.com/' + login)
                if now - cached['fetched_at'] < 300:
                    return dict(base, state='cached', message='Public GitHub data cached for up to five minutes.')
            if self.retry_after.get(key, 0) > now:
                return dict(base, state='stale' if cached else 'unavailable',
                            message='GitHub is temporarily unavailable or rate limited. Cached results are shown when available.',
                            retry_at=self.retry_after[key])
            try:
                result = dict(base, **fetch(login), fetched_at=now, state='live',
                              message='Latest successful refresh from the GitHub API.')
                temp = path.with_suffix('.tmp')
                temp.write_text(json.dumps(result), encoding='utf-8')
                temp.replace(path)
                return result
            except HTTPError as exc:
                try:
                    retry = float(exc.headers.get('Retry-After') or 0)
                    reset = float(exc.headers.get('X-RateLimit-Reset') or 0)
                except (ValueError, AttributeError):
                    retry = reset = 0
                self.retry_after[key] = max(now + 60, min(now + 3600, max(now + retry, reset)))
                message = ('GitHub API rate limit reached. We will retry after the cooldown.' if exc.code in (403, 429)
                           else 'GitHub could not provide this public account data. Try again later.')
            except (OSError, URLError, ValueError, TypeError, AttributeError):
                self.retry_after[key] = now + 60
                message = 'GitHub could not be reached. Check internet access; previous results remain available when cached.'
            return dict(base, state='stale' if cached else 'unavailable', message=message,
                        retry_at=self.retry_after[key])

    def _fetch_profile(self, login):
        item = self._request(f'https://api.github.com/users/{login}')
        if not isinstance(item, dict) or str(item.get('login', '')).lower() != login.lower():
            raise ValueError('Unexpected GitHub profile.')
        return dict(name=str(item.get('name') or login)[:150], bio=str(item.get('bio') or '')[:1000],
                    avatar_url=_web_url(item.get('avatar_url'), 'avatars.githubusercontent.com'),
                    location=str(item.get('location') or '')[:200], company=str(item.get('company') or '')[:200],
                    website=_web_url(item.get('blog')), followers=_number(item.get('followers')),
                    following=_number(item.get('following')), public_repos=_number(item.get('public_repos')),
                    joined_at=str(item.get('created_at') or '')[:50])

    def profile(self, login):
        return self._cached(login, 'profile', self._fetch_profile, {'name': login, 'avatar_url': '',
                            'bio': '', 'location': '', 'company': '', 'website': '',
                            'followers': None, 'following': None, 'public_repos': None, 'joined_at': ''})

    def _fetch_repositories(self, login):
        repos = []
        truncated = False
        for page in range(1, 11):
            data = self._request(f'https://api.github.com/users/{login}/repos?type=owner&sort=updated&direction=desc&per_page=100&page={page}')
            if not isinstance(data, list):
                raise ValueError('Unexpected GitHub repositories.')
            for item in data:
                if not isinstance(item, dict) or item.get('private', False):
                    continue
                url = _web_url(item.get('html_url'), 'github.com')
                if not url.startswith(f'https://github.com/{login}/'):
                    continue
                repos.append(dict(name=str(item.get('name', ''))[:150], url=url,
                    description=str(item.get('description') or '')[:1000],
                    language=str(item.get('language') or 'Unspecified')[:50],
                    stars=_number(item.get('stargazers_count')), forks=_number(item.get('forks_count')),
                    fork=bool(item.get('fork')), archived=bool(item.get('archived')),
                    updated_at=str(item.get('updated_at') or ''), pushed_at=str(item.get('pushed_at') or ''),
                    topics=[str(t)[:60] for t in (item.get('topics') or [])[:8]]))
            if len(data) < 100:
                break
            truncated = page == 10
        return dict(repos=repos, truncated=truncated)

    def repositories(self, login):
        result = self._cached(login, 'repos', self._fetch_repositories, {'repos': [], 'truncated': False})
        # Separate caches preserve repositories when only the profile request fails (and vice versa).
        return dict(result, profile=self.profile(login))

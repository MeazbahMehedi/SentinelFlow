/*
 * GitHub projects page: renders the two fixed developer accounts from the
 * cached /api/github/<login> endpoint. Text is inserted with textContent only.
 */
'use strict';

(function () {
  const accounts = [...document.querySelectorAll('[data-github-account]')];
  const data = new Map();
  const search = document.querySelector('#repo-search');
  const language = document.querySelector('#repo-language');
  const kind = document.querySelector('#repo-kind');
  const button = document.querySelector('#repo-refresh');
  const REFRESH_INTERVAL = 300000;
  const STATES = { live: 'Live refresh', cached: 'Cached', stale: 'Offline cache', unavailable: 'Unavailable' };
  let loading = false;

  const make = (tag, className, text) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  };

  const externalLink = (className, text, href) => {
    const link = make('a', className, text);
    link.href = href;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    return link;
  };

  function safeDate(value) {
    const date = new Date(value);
    return isNaN(date) ? 'Date unavailable' : date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }

  function renderProfile(section, profile) {
    const p = profile || { state: 'unavailable', message: 'Public profile is temporarily unavailable.' };
    const login = section.dataset.githubAccount;
    section.querySelector('[data-profile-name]').textContent = p.name || login;
    section.querySelector('[data-profile-bio]').textContent =
      p.bio || (p.state === 'unavailable' ? 'Open the GitHub profile above or refresh after reconnecting.' : 'No public bio on GitHub yet.');

    const details = section.querySelector('[data-profile-details]');
    details.replaceChildren();
    if (p.location) details.append(make('span', '', p.location));
    if (p.company) details.append(make('span', '', p.company));
    if (p.joined_at) details.append(make('span', '', 'Joined ' + safeDate(p.joined_at)));
    if (p.website) details.append(externalLink('text-link', 'Website ↗', p.website));

    const stats = section.querySelector('[data-profile-stats]');
    stats.replaceChildren();
    for (const [key, label] of [['public_repos', 'Public repos'], ['followers', 'Followers'], ['following', 'Following']]) {
      if (!Number.isInteger(p[key])) continue;
      const stat = make('div', '');
      stat.append(make('strong', '', p[key].toLocaleString()), make('span', '', label));
      stats.append(stat);
    }

    const fetched = p.fetched_at ? ' · Fetched ' + new Date(p.fetched_at * 1000).toLocaleString() : '';
    section.querySelector('[data-profile-status]').textContent =
      'Profile: ' + (STATES[p.state] || 'Unavailable') + fetched + '. ' + (p.message || '');

    const avatar = section.querySelector('[data-github-avatar]');
    const fallback = section.querySelector('[data-avatar-fallback]');
    avatar.onload = () => {
      avatar.hidden = false;
      fallback.hidden = true;
    };
    avatar.onerror = () => {
      avatar.hidden = true;
      fallback.hidden = false;
    };
    if (p.avatar_url) {
      const url = new URL(p.avatar_url);
      url.searchParams.set('s', '128');
      url.searchParams.set('sf_refresh', String(Math.floor((p.fetched_at || 0) / 300)));
      if (avatar.getAttribute('src') !== url.href) avatar.src = url.href;
    } else {
      avatar.removeAttribute('src');
      avatar.hidden = true;
      fallback.hidden = false;
    }
  }

  function matches(repo, query) {
    const text = (repo.name + ' ' + repo.description + ' ' + repo.topics.join(' ')).toLowerCase();
    return (
      (!query || text.includes(query)) &&
      (!language.value || repo.language === language.value) &&
      (!kind.value || (kind.value === 'fork' ? repo.fork : !repo.fork))
    );
  }

  function repositoryCard(repo) {
    const card = make('article', 'repository-card');
    const heading = make('div', 'repository-title');
    heading.append(
      externalLink('', repo.name, repo.url),
      make('span', 'pill', repo.archived ? 'ARCHIVED' : repo.fork ? 'FORK' : 'PUBLIC'),
    );
    card.append(heading, make('p', '', repo.description || 'No description provided.'));
    if (repo.topics.length) {
      const tags = make('div', 'repo-topics');
      repo.topics.forEach((topic) => tags.append(make('span', '', topic)));
      card.append(tags);
    }
    const meta = make('div', 'repository-meta');
    const lang = make('span', 'repo-language');
    const dot = make('i', 'language-dot');
    dot.dataset.language = repo.language;
    lang.append(dot, document.createTextNode(repo.language));
    meta.append(
      lang,
      make('span', '', '★ ' + repo.stars),
      make('span', '', '⑂ ' + repo.forks),
      make('span', 'repo-updated', 'Updated ' + safeDate(repo.updated_at)),
    );
    card.append(meta);
    return card;
  }

  function emptyState(info) {
    const unavailable = info.state === 'unavailable';
    const empty = make('div', 'empty');
    empty.append(
      make('strong', '', unavailable ? 'Projects are temporarily unavailable' : info.repos.length ? 'No matching repositories' : 'No public repositories yet'),
      make(
        'span',
        '',
        unavailable
          ? 'Use the profile link above or try again after the connection recovers.'
          : info.repos.length
            ? 'Try another keyword or filter.'
            : 'New public projects appear after the next successful refresh.',
      ),
    );
    return empty;
  }

  function render() {
    const query = search.value.trim().toLowerCase();
    let matching = 0;
    let total = 0;
    for (const section of accounts) {
      const info = data.get(section.dataset.githubAccount);
      if (!info) continue;
      const list = section.querySelector('[data-repo-list]');
      list.replaceChildren();
      total += info.repos.length;
      const repos = info.repos.filter((repo) => matches(repo, query));
      matching += repos.length;
      if (!repos.length) list.append(emptyState(info));
      else repos.forEach((repo) => list.append(repositoryCard(repo)));
    }
    document.querySelector('#repo-total').textContent = matching.toLocaleString() + ' matching / ' + total.toLocaleString() + ' loaded';
  }

  function renderStatus(section, info) {
    const badge = section.querySelector('[data-repo-state]');
    badge.textContent = STATES[info.state] || 'Unavailable';
    badge.className = 'badge ' + (info.state === 'live' ? 'finished' : info.state === 'cached' ? 'investigating' : 'paused');
    section.querySelector('[data-repo-count]').textContent = info.repos.length + ' public repos' + (info.truncated ? ' · latest 1,000' : '');
    section.querySelector('[data-repo-updated]').textContent = info.fetched_at
      ? 'Fetched ' + new Date(info.fetched_at * 1000).toLocaleTimeString()
      : 'No successful fetch yet';
    section.querySelector('[data-repo-message]').textContent = info.message;
  }

  async function fetchAccount(login) {
    try {
      const response = await fetch('/api/github/' + encodeURIComponent(login));
      if (!response.ok) throw new Error('Request failed');
      return await response.json();
    } catch (_) {
      const previous = data.get(login);
      return {
        login,
        profile: previous?.profile ? { ...previous.profile, state: 'stale', message: 'Unable to reconnect to the workspace.' } : null,
        repos: previous?.repos || [],
        state: previous ? 'stale' : 'unavailable',
        fetched_at: previous?.fetched_at || null,
        message: 'Unable to connect to the workspace. Refresh after reconnecting.',
      };
    }
  }

  async function load() {
    if (loading) return;
    loading = true;
    button.disabled = true;
    try {
      await Promise.all(
        accounts.map(async (section) => {
          const login = section.dataset.githubAccount;
          const info = await fetchAccount(login);
          data.set(login, info);
          renderStatus(section, info);
          renderProfile(section, info.profile);
        }),
      );
      const selected = language.value;
      const languages = [...new Set([...data.values()].flatMap((d) => d.repos.map((r) => r.language)))].sort();
      language.replaceChildren(new Option('All languages', ''));
      languages.forEach((l) => language.append(new Option(l, l)));
      language.value = languages.includes(selected) ? selected : '';
      render();
    } finally {
      loading = false;
      button.disabled = false;
    }
  }

  search.addEventListener('input', render);
  language.addEventListener('change', render);
  kind.addEventListener('change', render);
  button.addEventListener('click', load);
  load();
  setInterval(() => !document.hidden && load(), REFRESH_INTERVAL);
})();

# GitHub profiles: specification supplement, release 1.1.1

This supplement extends FR 54 and FR 55 of the bundled release 1.1 Word SRS. The rest of that specification remains applicable.

## Behavior

- GitHub Projects reads exactly `MeazbahMehedi` and `ItsMONIKAAKTER` from the code-owned `DEVELOPERS` tuple. Settings, profile edits, query parameters, and POST requests cannot replace either account.
- Each card reads GitHub’s public avatar URL, display name, bio, location, company, HTTPS website, join date, followers, following, and public repository count. Absent optional details are omitted; unavailable counts are not fabricated as zero.
- Images load from `https://avatars.githubusercontent.com`. The Content Security Policy permits this image origin only in addition to local/data images. Failed images fall back to initials. Text is inserted with `textContent`.
- Public repository cards include name, description, primary language, topics, stars, forks, archived/fork labels, and update dates. All pages are requested in batches of 100, up to 10 API pages/account; reaching this bound is explicitly labeled. Search and language/type filters apply across both accounts’ loaded projects.
- Profile and repository metadata use independent five-minute disk caches and independent failure/cooldown states. The page labels fresh, cached, stale, and unavailable states separately. Manual refresh respects cache and rate-limit cooldowns; a visible page polls every five minutes.
- The separate Developers page retains its administrator-controlled biographies, photos, and PDF CVs. Those local records never override the fixed GitHub Projects cards.

## Data flow and privacy

Browser → authenticated `GET /api/github/{fixed_login}` → GitHubProjects → independent caches → public GitHub REST profile and repository endpoints. The browser retrieves a validated avatar from GitHub’s avatar host. No GitHub token is required. Network captures, private projects, passwords, and CVs are never included in GitHub requests.

Cache files are `<login>.json` for repositories and `<login>.profile.json` for profiles in the existing `instance/github-cache` directory. Legacy repository caches continue to work; the profile cache populates automatically. No database migration is required.

## Acceptance criteria

1. Both fixed accounts appear on the GitHub Projects page without an edit control.
2. A GitHub profile edit appears after a successful cache refresh.
3. Multiple repositories and a second API page are displayed; private entries and unsafe links are excluded.
4. Losing one endpoint preserves the other endpoint’s available data; losing a previously fetched profile retains labeled stale data.
5. Accounts with no public repositories show an empty state; avatar errors show initials.
6. Attempts to POST account changes fail with method-not-allowed; unknown account GETs return 404.
7. The page retains the existing responsive layout, dark/light themes, and reduced-motion behavior.

GitHub sources: [public users](https://docs.github.com/en/rest/users/users#get-a-user) and [user repositories](https://docs.github.com/en/rest/repos/repos#list-repositories-for-a-user).

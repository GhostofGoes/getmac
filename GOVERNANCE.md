# Governance

getmac is a small, single-maintainer open source project. This document says how decisions are made, who holds which role, what each role is responsible for, and what happens if the maintainer can't continue.

## How decisions are made

The maintainer decides the scope and design of the project, what gets merged, and when releases happen. Anyone can take part in the discussion before a decision is made:

- Report a bug or propose a change in a [GitHub issue](https://github.com/GhostofGoes/getmac/issues).
- Ask questions and discuss ideas in [GitHub Discussions](https://github.com/GhostofGoes/getmac/discussions).
- Discuss a specific change in its pull request.

Decisions that change the project's scope or direction are recorded in [ROADMAP.md](https://github.com/GhostofGoes/getmac/blob/main/ROADMAP.md), which also lists what the project will not do. Day-to-day conventions (branch names, commit format, tests, formatting) are in [CONTRIBUTING.md](https://github.com/GhostofGoes/getmac/blob/main/CONTRIBUTING.md) and [AGENTS.md](https://github.com/GhostofGoes/getmac/blob/main/AGENTS.md). Larger design decisions are explained in the [architecture document](https://ghostofgoes.github.io/getmac/architecture.html).

## Roles

| Role | Who | Responsibilities |
|---|---|---|
| Maintainer | Christopher Goes ([@GhostofGoes](https://github.com/GhostofGoes)) | Decides the scope and design. Is the only [code owner](#code-owners), reviews pull requests and merges them. Answers issues and Discussions. Tags releases and checks them (see [releasing.md](https://github.com/GhostofGoes/getmac/blob/main/docs/misc_docs/releasing.md)). Holds the repository's owner rights, the PyPI project, and the GitHub Container Registry package. |
| Backup maintainer | Not yet named (see [Continuity](#continuity)) | Reviews and merges pull requests and handles issues when the maintainer asks. Takes over as maintainer if the maintainer can't continue. |
| Security contact | The maintainer | Receives private vulnerability reports and handles them as [SECURITY.md](https://github.com/GhostofGoes/getmac/blob/main/SECURITY.md) says. |
| Code of conduct contact | The maintainer | Receives and handles reports under the [Code of Conduct](https://github.com/GhostofGoes/getmac/blob/main/CODE_OF_CONDUCT.md). |
| Contributor | Anyone who opens an issue, a discussion, or a pull request | Follows [CONTRIBUTING.md](https://github.com/GhostofGoes/getmac/blob/main/CONTRIBUTING.md) and the Code of Conduct. Contributors are credited in the README. |

AI agents that change the repository are contributors. They follow the same rules, plus the [AI policy](https://github.com/GhostofGoes/getmac/blob/main/CONTRIBUTING.md#ai-policy) and [AGENTS.md](https://github.com/GhostofGoes/getmac/blob/main/AGENTS.md), and a human reviews their changes before they merge.

## Code owners

[`.github/CODEOWNERS`](https://github.com/GhostofGoes/getmac/blob/main/.github/CODEOWNERS) names the code owners. The only code owner is the maintainer, and the file names the maintainer for every file in the repository.

- GitHub asks a code owner to review each pull request that changes the files they own.
- The branch ruleset on `main` requires a code owner's approval before a pull request merges.
- GitHub doesn't let an author approve their own pull request. The maintainer merges their own pull requests through the ruleset's bypass for pull requests, and each such merge shows the bypass on the pull request.
- The maintainer decides who is a code owner. Change `.github/CODEOWNERS` only by pull request, and change this section in the same pull request. A code owner needs write access to the repository.

## Code review

Every change to `main` goes through a pull request, and a maintainer reviews it in GitHub's review tools before it merges. The reviewer reads the whole diff and checks that:

- The change does what its description says, and the project wants it ([ROADMAP.md](https://github.com/GhostofGoes/getmac/blob/main/ROADMAP.md)).
- New functionality has tests, and a bug fix has a regression test (see the [test policy](https://github.com/GhostofGoes/getmac/blob/main/CONTRIBUTING.md#code-requirements)).
- CI passes on the latest commit: lint, type checks, the test suite on every supported platform and Python version, the docs build, and the package build.
- Coverage hasn't decreased.
- The change doesn't add a dependency, a C extension, or a new way of running commands without a good reason, and it doesn't move a trust boundary. If it does, [SECURITY.md](https://github.com/GhostofGoes/getmac/blob/main/SECURITY.md) and the [assurance case](https://ghostofgoes.github.io/getmac/assurance.html) are updated in the same pull request.
- Command output samples and tests contain no real MAC addresses, IP addresses, or hostnames that shouldn't be public.
- The CHANGELOG and the documentation are updated when the change needs it.
- Commits follow Conventional Commits and carry a DCO sign-off, and AI-assisted changes follow the AI policy.

A pull request is acceptable when CI passes on its latest commit, the branch is up to date with `main`, and every review comment has been answered or resolved.

The goal is that at least half of all changes are reviewed by someone other than their author before a release. Pull requests from contributors are always reviewed by the maintainer. The maintainer's own pull requests are reviewed by the backup maintainer or another contributor when one is available; until a backup maintainer is named, the maintainer's own changes are self-reviewed, which is recorded as a gap in the [OpenSSF Best Practices](https://www.bestpractices.dev/projects/9388) badge entry.

## Access

Everyone with write access to the repository, or access to private vulnerability reports, must turn on two-factor authentication in GitHub. Use a passkey, a security key, or an authenticator app. Don't use SMS (text messages) as the only second factor. The maintainer checks this before giving a person access. The same applies to the PyPI account that owns the `getmac` project (releases are published with [Trusted Publishing](https://docs.pypi.org/trusted-publishers/), so no PyPI token is stored anywhere).

## Continuity

The project must be able to continue within a week if the maintainer can't continue: issues must still be created, labelled, and closed, pull requests reviewed and merged, and a release published.

Today, these need the maintainer's own access:

- Approving a pull request as code owner, or merging it through the ruleset's bypass.
- Tagging a release (the tag ruleset limits release tags to the maintainer). CI then builds, attests, and publishes the release to PyPI and the container registry, so no other credential is needed.
- The PyPI project and the GitHub Container Registry package, both of which publish through CI from this repository.

The plan to close this gap:

1. Name a backup maintainer and give them write access to the repository, so they can triage issues, answer Discussions, review pull requests, and merge pull requests that a code owner approved.
2. Keep the credentials for the three items above in emergency access (a password manager's emergency contact, or a sealed offline copy) that the backup maintainer can open if the maintainer can't continue. With them, the backup maintainer can tag a release and merge a pull request that makes them the code owner in `.github/CODEOWNERS` and in this file.
3. Add the backup maintainer as a co-owner of the `getmac` project on PyPI.

Until a backup maintainer is named, the project's bus factor is 1, and this is recorded in the badge entry. If you'd like to help with this role, open a Discussion.

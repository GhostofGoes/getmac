# Contributing to getmac

Thanks for taking an interest in this awesome little project. We love to bring new members into the community, and can always use the help.

## Resources
* Features suggestions and bug reports: [GitHub](https://github.com/GhostofGoes/getmac/issues)
* Discussion and general questions/help: [GitHub discussions](https://github.com/GhostofGoes/getmac/discussions) or the [Python Discord server](https://discord.gg/python)


## Code requirements

Your code *must*:
* Have tests
* Work with all *supported* Python versions
* Work on all *supported* platforms
* Pass linting (code quality checks)
* Pass CI (GitHub Actions)
* Adhere to the [Code of Conduct](CODE_OF_CONDUCT.md)
* Adhere to the [AI policy below](#ai-policy)
* Branch names and commits must follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) notation, e.g. a branch should be `feat-my-feature`, not `patch-1`, and commits should be `feat: myfeature description`, not `add some cool thing check it out`.

Most of these requirements are checked in CI (GitHub Actions), including Python versions and most supported platforms. Code is formatted with [Ruff's formatter](https://docs.astral.sh/ruff/formatter/). You can write whatever format you want, as long as you run the formatter before pushing, you're good (`pdm run format`).

Please be respectful and follow the [Code of Conduct](CODE_OF_CONDUCT.md). Memes, references, and jokes are OK. Be nice, we're all human (well, most of us), and code is the great equalizer.

### AI Policy

AI-assisted contributions are allowed, with the following requirements:

* [ ] All commits must include Co-Authorship indicating the commit was authored in-part or wholly by AI
* [ ] PR description must note that the contribution was authoried in-part or wholly by AI
* [ ] You (the human) must personally review all *non-test* changes by the AI. This is a small project, it's not a big ask. If it's obvious you have not done this, your PR will be closed, kthnxbai.
* [ ] It's OK to draft CHANGELOG and documentation with the AI, but please write it in your own words. AI-verbiage will be told once to be made human, second offence => PR closed.

This policy only applies to agent-powered AI contributions. It doesn't apply if you're just using AI tab-completion in an editor or a chatbot to answer questions or generate code snippets (unless the chatbot generates ALL your code, then it applies).

It's a (hopefully) straightforward and easy to follow policy. Therefore, if you don't follow this policy, you risk your PR being closed, and possibly being banned from the repo (and risk your GitHub account being suspended). I've had annoying bots on other repos, don't be that guy.

## Checklist before submitting a pull request
* [ ] Code is formatted using `ruff` (`pdm run format`)
* [ ] All tests run and pass locally
    * [ ] Tests: `pdm run test`
    * [ ] Benchmarks: `pdm run benchmark`
    * [ ] Lint: `pdm run lint`
* [ ] Update the [CHANGELOG](CHANGELOG.md) (if applicable, for non-trivial changes)
* [ ] Add your name to the contributors list in the [README](README.md) (please include what your contribution was after your name)
* [ ] (AI Bots) The AI policy was followed

## Checklist before a Pull Request will be merged
* [ ] *All* tests pass in GitHub Actions
* [ ] Code has been reviewed by at least one maintainer
* [ ] Coverage has NOT decreased


## Where to contribute

### Good for beginners
* Sample collection (see section below)
* Platform testing (see section below)
* Bug reports!
* Documentation (including fixes for grammar and spelling)
* Improving and adding tests for existing samples

### Main areas of focus
* Writing parsers for new commands (Example: `netsh int ipv6`)
* Addressing missing functionality (Example: default interface detection for IPv6 on Windows)
* Adding new features (Example: ability to find MAC by interface index integer)
* Adding tests for internal methods and mocking where necessary

### Platform testing
Help is dearly needed on testing and rooting out differences in various platforms and configurations. At a basic level, this involves just running the tests on any platforms you use. Open issues for any bugs or quirks you discover, or if you're feeling adventurous, fix it yourself!

**Any platform is fair game!** The following are platforms of special interest:
* MacOS/OSX (This requires owning a Mac, and is the area most sorely in need of testing)
* Legacy Windows (7, 8, 8.1)
* Windows Server (all versions)
* Arch Linux
* BSDs

### Sample collection
Collection examples of output of various commands is an easy way to contribute in a meaningful way.

Samples go in `tests/samples/`, in a folder named after the platform and version (e.g. `ubuntu_18.04`, `macos_10.12.6`, `windows_10`).

The easiest way is to run `scripts/collect_samples.py`. It runs all the commands getmac uses on your platform (plus a few related ones), and saves the output of each one to a `.out` file in `tests/samples/<platform>_<version>/`. It only needs Python 3.9+, getmac doesn't need to be installed, so you can copy it to any machine and run it there.

```bash
# See what would be run, without running anything
python scripts/collect_samples.py --dry-run

# Collect the samples
python scripts/collect_samples.py
```

Some notes:
* Existing samples aren't overwritten, unless you use `--force`
* Commands that aren't installed are skipped. Exit codes and errors are written to `collect_samples.log` in the same folder.
* Some commands only work as root or Administrator (e.g. `arping`).
* Run `python scripts/collect_samples.py --help` for all the options, e.g. `--name` to change the folder name, `--interface` and `--ip` to choose the interfaces and hosts to look up.

**Check the samples before committing them!** They have real MAC addresses, IP addresses, and hostnames from your machine. Replace anything you don't want to be public, and **use the same replacement everywhere** so the samples stay consistent.

#### To add a sample by hand
1. Run the command
2. Copy/paste the output (or redirect output, `tee` is helpful here) into a `.out` file in `tests/samples/<platform>_<version>/`. Name it after the command, e.g. `arp -a` is `arp_-a.out` and `ip route list 0/0` is `ip_route_list_0slash0.out`.
3. That's it!


## Getting started
1. Create your own fork of the code through GitHub web interface ([Here's a Guide](https://gist.github.com/Chaser324/ce0505fbed06b947d962))
1. Clone the fork to your computer. This can be done using the [GitHub desktop](https://desktop.github.com/) GUI , `git clone <fork-url>`, or the Git tools in your favorite editor or IDE.
1. Create and checkout a new branch in the fork with either your username (e.g. "ghostofgoes"), or the name of the feature or issue you're working on (e.g. "openbsd-support"). Again, this can be done using the GUI, your favorite editor, or `git checkout -b <branch> origin/<branch>`.
2. Install PDM: https://pdm-project.org/en/latest/#installation
3. Create local environment:
    ```bash
    pdm install -d
    ```
4. Ensure tests and linting works:
    ```bash
    pdm run lint
    pdm run test
    ```
5. Write some code! Git commit messages should information about what changed, and if it's relevant, the rationale (thinking) for the change.
6. Format your code:
   ```bash
    pdm run format
   ```
7. Follow the checklist in the pull request template
8. Submit a pull request!


## Bug reports
Filing a bug report:

1. Answer these questions:
    * [ ] What version of `getmac` are you using? (`getmac --version`)
    * [ ] What operating system and processor architecture are you using?
    * [ ] What version of Python are you using?
    * [ ] What did you do?
    * [ ] What did you expect to see?
    * [ ] What did you see instead?
2. Put any excessive output into a [GitHub Gist](https://gist.github.com/) and include a link in the issue.
3. Tag the issue with "Bug"

**NOTE**: If the issue is a potential security vulnerability, do *NOT* open an issue! Instead, email: ghostofgoes(at)gmail(dot)com


## Features and ideas
Ideas for features or other things are welcomed. Open an issue on GitHub detailing the idea, and tag it appropriately (e.g. "Feature" for a new feature).


## Resources

### Regex resources (regular expressions)
- https://pythex.org/
- https://regex101.com/
- [Python's `re` documentation](https://docs.python.org/3/library/re.html)
- [Python's guide to regex](https://docs.python.org/3/howto/regex.html) (this is actually really helpful)
- https://ultrapico.com/Expresso.htm (I haven't used this but it looks useful)


## Commands
```bash
# Create development environment
pdm install -d

# List scripts, these can be run with "pdm run"
pdm run -l

# Run tests
pdm run test

# Lint checks
pdm run lint

# Run getmac CLI
pdm run getmac --help
pdm run getmac --version
```

## Documentation

The docs are built using Sphinx. They are located in the `docs/` folder, and the configuration is in `docs/conf.py`.

To build docs locally:
```shell
pdm run docs
```

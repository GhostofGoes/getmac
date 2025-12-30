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

Most of these requirements are checked in CI (GitHub Actions), including Python versions and most supported platforms. Code is formatted with [Black](https://github.com/psf/black). You can write whatever format you want, as long as you run Black (`pdm run format`) before pushing, you're good.

Please be respectful and follow the [Code of Conduct](CODE_OF_CONDUCT.md). Memes, references, and jokes are OK. Be nice, we're all human, and code is the great equalizer.

## Checklist before submitting a pull request
* [ ] Code is formatted using `black` (`pdm run format`)
* [ ] All tests run and pass locally
    * [ ] Tests: `pdm run test`
    * [ ] Benchmarks: `pdm run benchmark`
    * [ ] Lint: `pdm run lint`
* [ ] Update the [CHANGELOG](CHANGELOG.md) (if applicable, for non-trivial changes)
* [ ] Add your name to the contributors list in the [README](README.md) (please include what your contribution was after your name)

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
Examples of output of various commands is an easy way contribute that is still incredibly helpful.
1. Run the command
2. Copy/paste the output (or redirect output of command, `tee` is helpful here) into an appropriately named `.out` file in `samples/`
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

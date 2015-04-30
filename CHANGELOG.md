# SavingThrow Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased][unreleased]

## [1.0.4] - 2015-04-30 - Dire Beetle
### Changed
- Formatted change log to adhere to [standards](http://keepachangelog.com/).
- Removes positional arguments meant to absorb Casper policy script variables $1-$3.
- Took SavingThrow out of beta (v.1.x.x)

### Fixed
- When run as a Casper policy script, does not handle optional arguments correctly, resulting in no action.

## [0.0.3] - 2015-04-14 - Gelatinous Cube
### Added

- Initial release.

### Changed (from prerelease and gist versions)
- Loads ADF (adware definition files) files from the internets.
- Caches ADF's locally in case network is down.
- New XML ADF format.
- Unloads launchd jobs prior to deletion.
- Kills processes.
- More command line options:
    - `-s` for regular old reporting to stdout (not in extension attribute format)
    - `-r` is still remove
    - `-q` quarantine files into a zip in your `/Library/Application Support/SavingThrow/Quarantine` folder

[unreleased]: https://github.com/sheagcraig/SavingThrow/compare/1.0.4...HEAD
[1.0.4]: https://github.com/sheagcraig/SavingThrow/compare/0.0.3...1.0.4
[0.0.3]: https://github.com/sheagcraig/SavingThrow/compare/3ef098d10e6155c5443f5fc05296f6be1d3adaa6...4892846c4313be8ff07edfaf853b1960c22ecdbf

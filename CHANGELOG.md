# SavingThrow Change Log

All notable changes to this project will be documented in this file. This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased][unreleased]

### Fixed
- Directories with trailing slashes blew up when trying to quarantine.

## [1.1.0] - 2015-09-18 - Mind Flayer
### Added
- `TestedFile` now adds a `FilenameRegex` and `Path` element to its allowed types of subelements.
	- Specify as many `Path` elements to folders as you want.
	- You may specify as many `FilenameRegex` elements to use to determine whether any of the files contained in the `Path`s match. A file being considered for being adware must only match _one_ of `FilenameRegex` (Logical OR).
	- You may now specify as many `Regex` elements of a `TestedFile` as you want. A file being considered for being adware must only match _one_ of `Regex` (Logical OR).
	- If you have specified a `Regex`, then the contents will also be tested before adding to the candidate list.
- You may now specify as many `File` elements in a `TestedFile` as you want also.
- Malformed XML will not stop SavingThrow from processing.
- Added `SavingThrowVersion` tag to top-level of ADFs. If the SavingThrow version is less than the one requested by the ADF, it will log a warning, and try to continue.

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

[unreleased]: https://github.com/sheagcraig/SavingThrow/compare/1.1.0...HEAD
[1.1.0]: https://github.com/sheagcraig/SavingThrow/compare/1.0.4...1.1.0
[1.0.4]: https://github.com/sheagcraig/SavingThrow/compare/0.0.3...1.0.4
[0.0.3]: https://github.com/sheagcraig/SavingThrow/compare/3ef098d10e6155c5443f5fc05296f6be1d3adaa6...4892846c4313be8ff07edfaf853b1960c22ecdbf

### 0.0.2 (UNRELEASED)

Initial release.

CHANGES (from prerelease and gist versions):
- Loads ADF (adware definition files) files from the internets.
- Caches ADF's locally in case network is down.
- New XML ADF format
- Unloads launchd jobs prior to deletion.
- Kills processes.
- More commandline options
	- -s for regular old reporting to stdout (not in extension attribute format)
	- -r is still remove
	- -q Quarantine files into a zip in your ```/Library/Application Support/SavingThrow/Quarantine``` folder

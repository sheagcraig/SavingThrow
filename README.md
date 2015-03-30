SavingThrow
=================
Work in progress, developing [AdwareCheckExtensionAttribute](https://gist.github.com/sheagcraig/69a473f00ce434fffd5b) into something a bit more flexible.

While there are plenty of products available to locate and remove Malware, Adware seems to be mostly left to its own devices. SavingThrow is a flexible script for allowing mac system administrators to curate lists of known Adware files (*Adware Definition Files*), to check for on managed computers, and optionally, remove or quarantine them. With time, administrators will hopefully pool their resources and research and develop a set of community best-practice Adware Definition Files akin to the AutoPkg recipe repos to help minimize the expertise required by any one adminstrator in dealing with these annoying pieces of software.

SavingThrow pulls its ADF's from user-provided URL's, and caches them locally, updating the cache as necessary.

SavingThrow can report back found Adware files as a Casper extension attribute (*no args*), straight to stdout (```-s/--stdout```), and always outputs its findings to the system log.

It can delete nefarious files (```-r/--remove```), or move them to a quarantine folder at ```/Library/Application Support/SavingThrow/<datetime>/``` (```-q/--quarantine```). Further, it will unload and disable LaunchD jobs prior to removal or quarantine to hopefully avoid requiring a reboot.

Adware Definition Files
=================
To configure a list of available ADF sources, edit the ```NEFARIOUS_FILE_SOURCES``` list at the top of SavingThrow.py to include each complete URL (including protocol), which you would like SavingThrow to use. Entries must be single or double quoted, and separated by commas.

Example of two extra ADF sources:
```
# Add any URL's to nefarious file lists here:
NEFARIOUS_FILE_SOURCES = ['https://ourserver.org/SavingThrow/CouponNagger.txt',
						  'https://ourserver.org/SavingThrow/ClickBait.txt']
```

SavingThrow includes the files described in Apple's [Kbase Article](https://support.apple.com/en-us/ht203987) on removing common adware as a default.

Adware files can be defined in two ways.

### Plain text file with one file path per line.
- Bash file globbing characters (```*, ?```) can be used for broader searching, or searching through an arbitrary number of homes, e.g.: ```/Users/*/Library/Preferences/com.crapware.agent.plist```
- Lines starting with # will be ignored as comments.

### XML files with the following structure are being developed for inclusion in an early preview build.
- Root level tag of AdwareDefinition.
- Files tag.
- One file tag per file path (including globs).

Plans are to include extra tags to help handle more complicated Adware checking routines (see Vsearch handling in SavingThrow.py code).

+1 to save against rods, staves, or wands.

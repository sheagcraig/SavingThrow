SavingThrow
===========
Work in progress, developing [AdwareCheckExtensionAttribute](https://gist.github.com/sheagcraig/69a473f00ce434fffd5b) into something a bit more flexible.

While there are plenty of products available to locate and remove Malware, Adware seems to be mostly left to its own devices. SavingThrow is a flexible script allowing mac system administrators to curate lists of known Adware files (*Adware Definition Files*), to check for on managed computers, and optionally, remove or quarantine them. With time, administrators will hopefully pool their resources and research and develop a set of community best-practice Adware Definition Files akin to the AutoPkg recipe repos to help minimize the expertise required by any one adminstrator in dealing with these annoying pieces of software. SavingThrow of course is not restricted to only software that is "Adware". Rather, it provides a system for flexibly managing lists of undesirable software on client machines and making them go away.

SavingThrow pulls its ADF's from user-provided URL's, and caches them locally, updating the cache as necessary.

SavingThrow can report back found Adware files as a Casper extension attribute (*no args*), or straight to stdout (```-s/--stdout```), and always outputs its findings to the system log.

It can delete nefarious files (```-r/--remove```), or move them to a quarantine folder at ```/Library/Application Support/SavingThrow/<datetime>/``` (```-q/--quarantine```). Further, it will unload and disable LaunchD jobs prior to removal or quarantine to hopefully avoid requiring a reboot.

Configuration
=============
SavingThrow requires admin privileges to run. Take note, it has the potential to delete a lot of files! It is the responsibility of each administrator to review and curate the ADF's configured for their institution.

To configure a list of available ADF sources, edit the ```NEFARIOUS_FILE_SOURCES``` list at the top of SavingThrow.py to include each complete URL (including protocol), which you would like SavingThrow to use. Entries must be single or double quoted, and separated by commas (it's a python list).

For example, say you wanted to add definitions for two extra ADF sources:
```
# Add any URL's to nefarious file lists here:
NEFARIOUS_FILE_SOURCES = ['https://ourserver.org/SavingThrow/CouponNagger.adf',
						  'https://ourserver.org/SavingThrow/ClickBait.'adf]
```

SavingThrow includes the files described in Apple's [Kbase Article](https://support.apple.com/en-us/ht203987) on removing common adware as a sane, trusted default.

If interest exists for a configuration plist, that would be simple to implement, although it would make use as an extension attribute more tricky (because it would require the config file be in place prior to meaningful inventory collection).

Adware Definition Files
=======================
Adware is defined in an XML formatted *Adware Definition File*. This section describes the ADF format and structure, as well as makes suggestions about some of the more complicated types.

In most cases, each adware "product" should be defined in its own file, although in some cases, grouping of adware products may make more sense. The ADF format allows an arbitrary number of Adware elements in one ADF file, should this be the case.

The top-level tag should be ```<AdwareDefinition>```, followed by metadata tags describing the document.
### Metadata Tags
- ```<Version>```: Version number of the ADF. This value should be incremented as changes are made over the lifetime of the definition.
- ```<DefinitionAuthor>```: The author of this ADF.
- ```<DefinitionSource>```: If the ADF is based on another ADF, provide original source URL's to aid others in researching.
- XML Comments for other top-level notes can go here as well.

### Adware Elements
Each adware "product" should be wrapped in an ```<Adware>``` tag.

If at all possible, include a source for downloading the adware so interested or OCD admins can test or verify the contents of the definition. Provide as many URLs as needed, each wrapped in ```<AdwareSource>``` tags.

The simplest adware element is ```<File>```. ```<File>``` defines a single file path to look for. The path can include standard shell globbing characters (```*?[a-z]```, etc) and text substitution as described below. No tilde expansions are performed.

Files with ambiguous, misleading, dynamically renamed, or obfuscated filenames or paths can be identified with a ```<TestedFile>``` element. Each ```<TestedFile>``` element must include a ```<File>``` and a ```<Regex>``` element, and may optionally include a ```ReplacementKey```.
```<File>```: As per the standard ```<File>``` tag above; also allows standard globbing characters. This file will be opened and searched using the...
```<Regex>```: A regular expression that matches some text in this ```<File>```. May include *one* group, indicated by ```( )```'s, which will become the value of ```<ReplacementKey>``` in the text replacement dictionary. 
```<ReplacementKey>```: If provided, will add or update the text replacement dictionary with the ```<ReplacementKey>``` value as the key, and uses the first group result from the above regex search as a value.

An example of how this is used can be seen in the default ADF:
```
<TestedFile>
	<Filename>/Library/LaunchAgents/com.*.agent.plist</Filename>
	<Regex>.*/Library/Application Support/(.*)/Agent/agent.app/Contents/MacOS/agent</Regex>
	<ReplacementKey>AGENT</ReplacementKey>
</TestedFile>
<TestedFile>
	<Filename>/Library/LaunchDaemons/com.*.helper.plist</Filename>
	<Regex>.*/Library/Application Support/(.*)/Agent/agent.app/Contents/MacOS/agent</Regex>
	<ReplacementKey>AGENT</ReplacementKey>
</TestedFile>
<TestedFile>
	<Filename>/Library/LaunchDaemons/com.*.daemon.plist</Filename>
	<Regex>.*/Library/Application Support/(.*)/Agent/agent.app/Contents/MacOS/agent</Regex>
	<ReplacementKey>AGENT</ReplacementKey>
</TestedFile>
<File>/Library/LaunchAgents/com.%AGENT%.agent.plist</File>
<File>/Library/LaunchDaemons/com.%AGENT%.helper.plist</File>
<File>/Library/LaunchDaemons/com.%AGENT%.daemon.plist</File>
<File>/Library/Application Support/%AGENT%</File>
```
In this example, ```<TestedFile>``` is being used to discover the obfuscated name of the VSearch agent. Each incarnation of this Adware seems to have a different "name", for example "projectX". This name can be found by regex searching with the provided pattern, as a ```/Library/Application Support``` subfolder in several of the LaunchD jobs it installs. The ```<Regex>``` confirms that these files, despite having a globbed filename (e.g. ```com.*.agent.plist```), are related to the adware, and not just false positives. We know this, because these files launch the ```agent``` binary. This regex has used parentheses to group the variable name, and added the value to the replcement dict with the key ```AGENT```.

Later, in the following group of ```<File>``` elements, this value is then swapped into the ```%AGENT%``` section of the path (see Text Substitution below). Given our example name of "projectX", one filename then becomes ```/Library/LaunchDaemons/com.projectX.daemon.plist```.

#### Text Substitution
```<File>``` elements can make use of text substitution using the results of a regular expression search from a ```<TestedFile>``` operation. A substitution is indicated by wrapping the ```ReplacementKey``` in ```%``` characters, e.g. ```<File>/Library/LaunchAgents/com.%AGENT%.helper.plist</File>```. ```<TestedFile>``` elements are found and searched prior to ```<File>``` searching.

### Process
If an adware product has a recognizeable process name, put the name in a ```<Process>``` element contained within a ```<Adware>``` tree, and SavingThrow can search for any instances of that process running and kill them. SavingThrow uses the bash shell command ```pgrep``` to search for running processes, which you can use to test your own process definitions.

To eliminate false positives, SavingThrow takes the process name defined in the ```<Process>``` tag, and converts it to a regular expression that matches *ONLY* that name (with regex-reserved characters escaped). This is to say that, for example, if you define a ```<Process>dbf</Process>```, it will generate a pgrep regex of ```^dbf$```, which will match a process named exactly ```dbf```, but NOT match the Apple process ```dbfseventsd```, which ```pgrep dbf``` would match.

### Case Sensitivity
Apple, despite appearances, configures drive partitions with a case-*insensitive* filesystem. Python is happy to believe this, and files will match even if the capitalization in the definition does not match that on the filesystem. That being said, please provide the "correct" capitalization in your definitions.

This can be used to your advantage as well. In the example above, the ```<Regex>``` group actually matches with ```projectX``` in the file's text. However, this capitalization is not consistent in all places; in some places it is ```projectX``` and others it is ```projectx```. Due to the case insensitivity, however, when this value gets substituted in, even though the filename does not match the "real" filename's capitalization, SavingThrow still detects it.

+1 to save against rods, staves, or wands.

![Image of Gelatinous Cube](http://media.tumblr.com/1f75ab89cd54f34d7441afb1bf4442c3/tumblr_inline_mzsyks2vh31qfgehu.png)

#!/usr/bin/python
"""SavingThrow

Identify or remove files known to be involved in Adware/Malware
infection.

Most of the code applies to building a list of malware files. Thus,
both extension attribute and removal handling are included.

Cleans files as a Casper script policy if --remove is passed as an arg.

"""

import glob
import os
import re
import shutil
import sys
import syslog
import urllib2


# Add any URL's to nefarious file lists here:
# Default is to at least use Apple's files from:
# https://support.apple.com/en-us/ht203987
NEFARIOUS_FILE_SOURCES = []
NEFARIOUS_FILE_SOURCES.append('https://gist.githubusercontent.com/sheagcraig/5c76604f823d45792952/raw/8e8eaa9f69905265912ccc615949505558ff40f6/AppleAdwareList')

CACHE = '/usr/local/share/'

known_malware = set()

for source in NEFARIOUS_FILE_SOURCES:
    try:
        syslog.syslog(syslog.LOG_ALERT, "Attempting to update Adware list: %s" % source)
        malware_list = urllib2.urlopen(source).read()

        # Update our cached copy
        with open(os.path.join(CACHE, os.path.basename(source)), 'w') as f:
            f.write(malware_list)

    except urllib2.URLError as e:
        # Use the cached copy if it exists.
        syslog.syslog(syslog.LOG_ALERT, "Update failed: %s. Looking for cached copy" % e.message)
        with open(os.path.join(CACHE, os.path.basename(source)), 'r') as f:
            malware_list = f.read()

    known_malware.update({file for file in malware_list.split('\n')})
print(known_malware)

found_malware = {match for filename in known_malware for match in
                 glob.glob(filename)}

# Look for "ProjectX" variants.
# This adware seems to have a different name each time it pops up.
# Apple's solution is too broad. We look at the files Apple suggests,
# but then also search within to see if they are calling a known
# binary file, "agent.app/Contents/MacOS/agent".
projectx_files = {
    '/Library/LaunchAgents/com.*.agent.plist',
    '/Library/LaunchDaemons/com.*.helper.plist',
    '/Library/LaunchDaemons/com.*.daemon.plist',
}

projectx_candidates = {match for filename in projectx_files for match in
                 glob.glob(filename)}

agent_regex = re.compile('.*/Library/Application Support/(.*)/Agent/agent.app/Contents/MacOS/agent')
for candidate in projectx_candidates:
    with open(candidate, 'r') as candidate_file:
        launchd_job = candidate_file.read()

    if re.search(agent_regex, launchd_job):
        found_malware.add(candidate)
        # If we find a Launch[Agent|Daemon] that has ProgramArguments
        # which runs "agent", find the unique name for this instance.
        # We can then use it to find the Application Support folder.
        obfuscated_name = re.search(agent_regex, launchd_job).group(1)
        found_malware.add('/Library/Application Support/%s' % obfuscated_name)

# Is this an EA or a script execution (Casper scripts always have 3
# args, so we can't just use the first argument.
if len(sys.argv) == 1:
    # Extension attribute (First arg is always script name).
    result = '<result>'
    if found_malware:
        result += 'True\n'
        for item in enumerate(found_malware):
            result += "%d: %s\n" % item
    else:
        result += 'False'

    print('%s</result>' % result)

elif "--remove" in sys.argv:
    # Removal script.
    syslog.syslog(syslog.LOG_ALERT, "Looking for malware")
    for item in found_malware:
        try:
            if os.path.isdir(item):
                shutil.rmtree(item)
            elif os.path.isfile(item):
                os.remove(item)
            syslog.syslog(syslog.LOG_ALERT, "Removed malware file:  %s" % item)
        except OSError as e:
            syslog.syslog(syslog.LOG_ALERT,
                          "Failed to remove malware file:  %s, %s" % (item, e))

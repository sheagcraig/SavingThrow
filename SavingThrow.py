#!/usr/bin/python
"""SavingThrow

Identify or remove files known to be involved in Adware/Malware
infection.

Most of the code applies to building a list of malware files. Thus,
both extension attribute and removal handling are included.

Cleans files as a Casper script policy if --remove is passed as an arg.

Copyright (C) 2015 Shea G Craig <shea.craig@da.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""

import argparse
import glob
import os
import re
import shutil
import sys
import syslog
import time
import urllib2


# Add any URL's to nefarious file lists here:
NEFARIOUS_FILE_SOURCES = []
# File format is one path per line.
# Files to look for may include globbing characters
# Default is to at least use Apple's files from:
# https://support.apple.com/en-us/ht203987
NEFARIOUS_FILE_SOURCES.append('https://gist.githubusercontent.com/sheagcraig/5c76604f823d45792952/raw/8e8eaa9f69905265912ccc615949505558ff40f6/AppleAdwareList')


CACHE = '/Library/Application Support/SavingThrow'
if not os.path.exists(CACHE):
    os.mkdir(CACHE)


def build_argparser():
    """Create our argument parser."""
    parser = argparse.ArgumentParser(description="Modular Adware/Malware "
                                     "Extension Attribute and Removal Script")
    parser.add_argument('jamf-arguments', nargs='*')
    parser.add_argument('-v', '--verbose', action="store_true")
    mode_parser = parser.add_mutually_exclusive_group()
    mode_parser.add_argument(
        "-r", "--remove", help="Remove offending files.", action='store_true')
    mode_parser.add_argument(
        "-q", "--quarantine", help="Move offending files to quarantine "
        "location.", action='store_true')

    return parser


def log(message):
    # TODO log and optionally print with verbose flag on
    pass


def main():

    # Handle command line arguments
    parser = build_argparser()
    args = parser.parse_args()

    known_malware = set()

    for source in NEFARIOUS_FILE_SOURCES:
        try:
            syslog.syslog(syslog.LOG_ALERT,
                        "Attempting to update Adware list: %s" % source)
            malware_list = urllib2.urlopen(source).read()

            # Update our cached copy
            with open(os.path.join(CACHE, os.path.basename(source)), 'w') as f:
                f.write(malware_list)

        except urllib2.URLError as e:
            # Use the cached copy if it exists.
            syslog.syslog(syslog.LOG_ALERT,
                        "Update failed: %s. Looking for cached copy" % e.message)
            with open(os.path.join(CACHE, os.path.basename(source)), 'r') as f:
                malware_list = f.read()

        known_malware.update({file for file in malware_list.split('\n')})

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
        '/Library/LaunchDaemons/com.*.daemon.plist'}

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

    # Is this an EA or a script execution
    if args.remove:
        # Removal script.
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

    elif args.quarantine:
        # Quarantine script.
        if found_malware:
            backup_dir = os.path.join(CACHE, time.strftime("%Y%m%d-%H%M%S"))
            os.mkdir(backup_dir)

        for item in found_malware:
            try:
                shutil.move(item, backup_dir)
                syslog.syslog(syslog.LOG_ALERT, "Quarantined malware file:  %s"
                            % item)
            except OSError as e:
                syslog.syslog(syslog.LOG_ALERT,
                            "Failed to quarantine malware file:  %s, %s"
                            % (item, e))

    else:
        # Extension attribute (First arg is always script name).
        result = '<result>'
        if found_malware:
            result += 'True\n'
            for item in enumerate(found_malware):
                result += "%d: %s\n" % item
        else:
            result += 'False'

        print('%s</result>' % result)


if __name__ == '__main__':
    main()

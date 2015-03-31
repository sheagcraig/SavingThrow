#!/usr/bin/python
"""SavingThrow

Identify or remove files known to be involved in Adware infection,
based on curated lists of associated files.

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

# Import ALL the modules!
import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import syslog
import time
import urllib2
import zipfile
import zlib


__version__ = '0.0.1'


# Add any URL's to nefarious file lists here:
NEFARIOUS_FILE_SOURCES = []
# File format is one path per line.
# Files to look for may include globbing characters.
# Default is to at least use Apple's files from:
# https://support.apple.com/en-us/ht203987
NEFARIOUS_FILE_SOURCES.append('https://gist.githubusercontent.com/sheagcraig/5c76604f823d45792952/raw/AppleAdwareList')
#DEBUG
NEFARIOUS_FILE_SOURCES.append('https://gist.github.com/sheagcraig/13850488350aef95c828/raw/TestFilesList')

CACHE = '/Library/Application Support/SavingThrow'
if not os.path.exists(CACHE):
    os.mkdir(CACHE)


class Logger():
    """Simple logging class."""
    def __init__(self, verbose=False):
        self.verbose = verbose

    def log(self, message, log_level=syslog.LOG_ALERT):
        """Log to the syslog, and if verbose, also to stdout."""
        syslog.syslog(log_level, message)
        if self.verbose:
            print(message)

    def vlog(self, message, log_level=syslog.LOG_ALERT):
        """Log to the syslog, and to stdout."""
        syslog.syslog(log_level, message)
        print(message)


# Make our global logger.
logger = Logger()


def build_argparser():
    """Create our argument parser."""
    description = ("Modular Adware Extension Attribute and "
                   "Removal Script. Call with no arguments to run as "
                   "an extension attribute, or with --remove or "
                   "--quarantine to operate as a cleanup tool.")
    epilog = ("Roll to save against paralyzation, lest the Gelatinous "
              "Cube anesthetizes, and ultimately, digests you.")
    parser = argparse.ArgumentParser(description=description, epilog=epilog)
    help = ("Accepts all passed positional arguments (or none) to "
            "allow Casper script usage.")
    parser.add_argument('jamf-arguments', nargs='*', help=help)
    parser.add_argument('-v', '--verbose', action="store_true",
                        help="Print to stdout as well as syslog.")
    mode_parser = parser.add_mutually_exclusive_group()
    mode_parser.add_argument(
        "-s", "--stdout", help="Print standard report.", action='store_true')
    mode_parser.add_argument(
        "-r", "--remove", help="Remove offending files.", action='store_true')
    mode_parser.add_argument(
        "-q", "--quarantine", help="Move offending files to quarantine "
        "location.", action='store_true')

    return parser


def get_projectX_files():
    """Return a set of vSearch agent-related LaunchD configuration
    files.

    This adware seems to have a different name each time it pops up.
    Apple's solution is too broad. We look at the files Apple suggests,
    but then also search within to see if they are calling a known
    binary file, "agent.app/Contents/MacOS/agent".

    """
    projectx_files = {
        '/Library/LaunchAgents/com.*.agent.plist',
        '/Library/LaunchDaemons/com.*.helper.plist',
        '/Library/LaunchDaemons/com.*.daemon.plist'}

    projectx_candidates = {match for filename in projectx_files for match in
                    glob.glob(filename)}

    agent_regex = re.compile('.*/Library/Application Support/(.*)/Agent/agent.app/Contents/MacOS/agent')
    result = set()

    for candidate in projectx_candidates:
        with open(candidate, 'r') as candidate_file:
            launchd_job = candidate_file.read()

        if re.search(agent_regex, launchd_job):
            result.add(candidate)
            # If we find a Launch[Agent|Daemon] that has ProgramArguments
            # which runs "agent", find the unique name for this instance.
            # We can then use it to find the Application Support folder.
            obfuscated_name = re.search(agent_regex, launchd_job).group(1)
            result.add('/Library/Application Support/%s' % obfuscated_name)

    return result


def get_adware_description(source):
    """Given a URL to an adware description file, attempt to
    download, parse, and generate a set of targeted files and processes.

    """
    try:
        logger.log("Attempting to update Adware list: %s" % source)
        adware_text = urllib2.urlopen(source).read()
        cache_file = os.path.basename(source)
        # Handle URLs which don't point at a specific file. e.g.
        # Permalinked gists can be referenced with a directory URL.
        if not cache_file:
            # Remove the protocol and swap slashes to periods.
            # Drop the final slash (period).
            cache_file = source.split("//")[1].replace("/", ".")[:-1]
        cache_path = os.path.join(CACHE, cache_file)

        # Update our cached copy.
        try:
            with open(cache_path, 'w') as f:
                f.write(adware_text)
        except IOError as e:
            if e[0] == 13:
                print("Please run as root!")
                sys.exit(13)
            else:
                raise e

    except urllib2.URLError as e:
        # Use the cached copy if it exists.
        logger.log("Update failed: %s. Looking for cached copy" %
                    e.message)
        try:
            with open(cache_path, 'r') as f:
                adware_text = f.read()
        except IOError as e:
            logger.log("Error: No cached copy of %s or other error %s" %
                    (source, e.message))

    adware_list = {item.strip() for item in adware_text.splitlines() if not
                    item.startswith('#') and len(item.strip()) != 0}
    known_adware = {file for file in adware_list if file.startswith('/')}
    processes = {item.split(":")[1].strip() for item in adware_list if
                 item.startswith('PROCESS:')}

    return (known_adware, processes)


def remove(files):
    """Delete identified files and directories."""
    unload_and_disable_launchd_jobs(files)
    for item in files:
        try:
            if os.path.isdir(item):
                shutil.rmtree(item)
            elif os.path.isfile(item):
                os.remove(item)
            logger.log("Removed adware file(s):  %s" % item)
        except OSError as e:
            logger.log("Failed to remove adware file(s):  %s, %s" % (item, e))


def quarantine(files):
    """Move all identified files to a timestamped folder in our cache.

    """
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    # Let's not bother if the list is empty.
    if files:
        quarantine_dir = os.path.join(CACHE, 'Quarantine')
        if not os.path.exists(quarantine_dir):
            os.mkdir(quarantine_dir)
        backup_dir = os.path.join(quarantine_dir, timestamp)
        os.mkdir(backup_dir)

        unload_and_disable_launchd_jobs(files)

        for item in files:
            try:
                shutil.move(item, backup_dir)
                logger.log("Quarantined adware file(s):  %s" % item)
            except OSError as e:
                logger.log("Failed to quarantine adware file(s):  %s, %s" %
                        (item, e))

        zpath = os.path.join(quarantine_dir, "%s-Quarantine.zip" % timestamp)
        with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as zipf:
            os.chdir(backup_dir)
            for item in files:
                zipf.write(os.path.basename(item))

        logger.log("Zipped quarantined files to:  %s" % zpath)

        shutil.rmtree(backup_dir)


def report_to_stdout(files):
    """Report back on identified files."""
    result = 'Adware files found: %s\n' % len(files)
    if files:
        for item in enumerate(files):
            result += "%d: %s\n" % item

    logger.vlog(result)


def extension_attribute(files):
    """Report back on identified files in a Casper extension attribute
    format.

    """
    result = '<result>'
    if files:
        result += 'True\n'
        for item in enumerate(files):
            result += "%d: %s\n" % item
    else:
        result += 'False'

    result += '</result>'

    logger.vlog(result)


def unload_and_disable_launchd_jobs(files):
    """Given an iterable of paths, attempt to unload and disable any
    launchd configuration files.

    """
    # Find system-level LaunchD config files.
    conf_locs = {'/Library/LaunchAgents',
                 '/Library/LaunchDaemons',
                 '/System/Library/LaunchAgents',
                 '/System/Library/LaunchDaemons'}

    # Add valid per-user config locations.
    for user_home in os.listdir('/Users'):
        candidate_launchd_loc = os.path.join('/Users', user_home,
                                             'Library/LaunchAgents')
        if os.path.exists(candidate_launchd_loc):
            conf_locs.add(candidate_launchd_loc)
    launchd_config_files = {file for file in files for conf_loc in conf_locs if
                            file.find(conf_loc) == 0}

    # Attempt to unload and disable these files.
    for file in launchd_config_files:
        try:
            subprocess.check_call(['launchctl', 'unload', '-w', file])
        except subprocess.CalledProcessError as e:
            # Job may not be loaded, so just log and move on.
            logger.log(e)


def kill(processes):
    """Given a list of running process ids, try to kill them."""
    for process_id in processes:
        try:
            result = subprocess.check_call(['kill', process_id])
            logger.log("Killed process ID: %s" % process_id)
        except subprocess.CalledProcessError:
            logger.log("Failed to kill process ID: %s" % process_id)


def get_running_process_IDs(processes):
    """Given a list of process names, return a list of process ID's with
    that name currently running.

    """
    running_process_ids = []
    for process in processes:
        safe_process = '^%s$' % re.escape(process)
        try:
            pids = subprocess.check_output(['pgrep', safe_process]).splitlines()
            running_process_ids.extend(pids)
        except subprocess.CalledProcessError:
            # No results
            pass
    return running_process_ids


def main():
    """Manage arguments and coordinate our saving throw."""
    # Handle command line arguments.
    parser = build_argparser()
    args = parser.parse_args()

    if args.verbose:
        logger.verbose = True

    known_adware = set()
    processes = set()
    for source in NEFARIOUS_FILE_SOURCES:
        adware_files, adware_processes = get_adware_description(source)
        known_adware.update(adware_files)
        processes.update(adware_processes)

    # Look for projectX files.
    known_adware.update(get_projectX_files())

    # Build a set of adware files that are on the drive.
    found_adware = {match for filename in known_adware for match in
                    glob.glob(filename)}

    # Build a set of pids we need to kill.
    found_processes = get_running_process_IDs(processes)

    # Which action should we perform? An EA has no arguments, so make
    # it the default.
    if args.remove:
        remove(found_adware)
        kill(found_processes)
    elif args.quarantine:
        quarantine(found_adware)
        kill(found_processes)
    elif args.stdout:
        report_to_stdout(found_adware)
    else:
        extension_attribute(found_adware)


if __name__ == '__main__':
    main()

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
from xml.etree import ElementTree
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


__version__ = '0.0.2'


# Add any URL's to nefarious file lists here:
NEFARIOUS_FILE_SOURCES = []
# File format is one path per line.
# Files to look for may include globbing characters.
# Default is to at least use Apple's files from:
# https://support.apple.com/en-us/ht203987
#NEFARIOUS_FILE_SOURCES.append('https://gist.githubusercontent.com/sheagcraig/5c76604f823d45792952/raw/AppleAdwareList')
NEFARIOUS_FILE_SOURCES.append('https://gist.githubusercontent.com/sheagcraig/86c2cda271cb16736987/raw/TestXML.adf')
#DEBUG
#NEFARIOUS_FILE_SOURCES.append('https://gist.github.com/sheagcraig/13850488350aef95c828/raw/TestFilesList')

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


class AdwareController():
    """Manages a group of Adware objects."""
    def __init__(self, adwares=[]):
        """Create a controller, optionally populating the list of
        adwares.

        """
        self.adwares = adwares

    def add_adware_from_url(self, source):
        """Given a URL to an adware description file, attempt to
        download, parse, and generate a set of targeted files and processes,
        and add to internal adwares list.

        """
        cache_file = os.path.basename(source)
        # Handle URLs which don't point at a specific file. e.g.
        # Permalinked gists can be referenced with a directory URL.
        if not cache_file:
            # Remove the protocol and swap slashes to periods.
            # Drop the final slash (period).
            cache_file = source.split("//")[1].replace("/", ".")[:-1]
        cache_path = os.path.join(CACHE, cache_file)

        try:
            logger.log("Attempting to update Adware list: %s" % source)
            adware_text = urllib2.urlopen(source).read()

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

        self.adwares.extend(
            [Adware(adware) for adware in
             ElementTree.fromstring(adware_text).findall('Adware')])

    def report_string(self):
        """Return a nicely formatted string representation of
        findings.

        """
        result = ''
        for adware in self.adwares:
            if adware.found or adware.processes:
                result += "Name: %s\n" % adware.name
                for num, found in enumerate(
                    adware.found, 1):
                    result += "File %s: %s\n" % (num, found)
                for num, found in enumerate(
                    adware.processes.items(), 1):
                        pids_string = ', '.join((str(pid) for pid in found[1]))
                        result += "Process %s: %s PID: %s\n" % (
                            num, found[0], pids_string)

        return result

    def report_to_stdout(self):
        """Report back on identified files."""
        report_string = self.report_string()
        if report_string:
            result = 'Adware files and processes found:\n%s' % report_string
        else:
            result = 'No adware files or processes found.'

        logger.vlog(result)

    def extension_attribute(self):
        """Report back on identified files in a Casper extension attribute
        format.

        """
        result = '<result>'
        report_string = self.report_string()
        if report_string:
            result += 'True\n%s' % report_string
        else:
            result += 'False'

        result += '</result>'
        logger.vlog(result)

    def remove(self):
        """Delete identified files and directories."""
        files = [file for adware in self.adwares for file in adware.found]
        self.unload_and_disable_launchd_jobs(files)
        for item in files:
            try:
                if os.path.isdir(item):
                    shutil.rmtree(item)
                elif os.path.isfile(item):
                    os.remove(item)
                logger.log("Removed adware file(s):  %s" % item)
            except OSError as e:
                logger.log("Failed to remove adware file(s):  %s, %s" % (item, e))

    def quarantine(self):
        """Move all identified files to a timestamped folder in our cache.

        """
        files = [file for adware in self.adwares for file in adware.found]
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        # Let's not bother if the list is empty.
        if files:
            quarantine_dir = os.path.join(CACHE, 'Quarantine')
            if not os.path.exists(quarantine_dir):
                os.mkdir(quarantine_dir)
            backup_dir = os.path.join(quarantine_dir, timestamp)
            os.mkdir(backup_dir)

            self.unload_and_disable_launchd_jobs(files)

            for item in files:
                try:
                    shutil.move(item, backup_dir)
                    logger.log("Quarantined adware file(s):  %s" % item)
                except OSError as e:
                    logger.log("Failed to quarantine adware file(s):  %s, %s" %
                            (item, e))

            zpath = os.path.join(quarantine_dir, "%s-Quarantine.zip" %
                                 timestamp)
            with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as zipf:
                os.chdir(backup_dir)
                for item in files:
                    zipf.write(os.path.basename(item))

            logger.log("Zipped quarantined files to:  %s" % zpath)

            shutil.rmtree(backup_dir)

    def unload_and_disable_launchd_jobs(self, files):
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
        launchd_config_files = {file for file in files for conf_loc in
                                conf_locs if file.find(conf_loc) == 0}

        # Attempt to unload and disable these files.
        for file in launchd_config_files:
            logger.log('Unloading %s' % file)
            result = ''
            try:
                # Toss out any stderr messages about things not being
                # loaded. We just want them off; don't care if they're
                # not running to begin with.
                result = subprocess.check_output(['launchctl', 'unload', '-w',
                                                  file],
                                                 stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                # Job may not be loaded, so just log and move on.
                result = e.message
            finally:
                if result:
                    logger.log('Launchctl response: %s' % result)

    def kill(self):
        """Given a list of running process ids, try to kill them."""
        kill_list = [pid for adware in self.adwares for process in
                     adware.processes.values() for pid in process]
        for process_id in kill_list:
            try:
                result = subprocess.check_call(['kill', str(process_id)])
                logger.log("Killed process ID: %s" % process_id)
            except subprocess.CalledProcessError:
                logger.log("Failed to kill process ID: %s" % process_id)


class Adware():
    """Represents one adware 'product', as defined in an Adware
    Definition File (ADF).

    """
    def __init__(self, xml):
        """Given an Element describing an Adware, setup, and find
        adware files.

        """
        self.xml = xml
        self.env = {}
        self.found = set()
        self.processes = {}
        self.name = self.xml.findtext('AdwareName')

        self.find()

    def find(self):
        """Identify files on the system that correspond to this
        Adware.

        """
        candidates = set()
        process_candidates = set()
        # First look for regex-confirmed files to prepare for text
        # replacement.
        files_to_test = self.xml.findall('TestedFile')
        for tested_file in files_to_test:
            regex = re.compile(tested_file.findtext('Regex'))
            replacement_key = tested_file.findtext('ReplacementKey')
            fnames = glob.glob(tested_file.findtext('File'))
            for fname in fnames:
                with open(fname, 'r') as f:
                    text = f.read()

                if re.search(regex, text):
                    candidates.add(fname)

                    if replacement_key:
                        self.env[replacement_key] = re.search(regex,
                                                              text).group(1)

        # Now look for regular files.
        for std_file in self.xml.findall('File'):
            # Perform text replacments
            if "%" in std_file.text:
                for key, value in self.env.items():
                    std_file.text = std_file.text.replace(
                        "%%%s%%" % key, value)
            candidates.add(std_file.text)

        # Find files on the drive.
        # OS X is case insensitive, so we have to test to avoid
        # including duplicates in the case *sensitive* set.
        matches = {match for filename in candidates for match in
                   glob.glob(filename) if os.path.basename(match) in
                   os.listdir(os.path.dirname(match))}
        self.found.update(matches)

        # Build a set of processes to look for.
        process_candidates = {process.text for process in
                              self.xml.findall('Process')}

        # Find running processes.
        self.get_running_process_IDs(process_candidates)

    def get_running_process_IDs(self, processes):
        """Given a list of process names, get running process ID's"""
        running_process_ids = {}
        for process in processes:
            safe_process = '^%s$' % re.escape(process)
            try:
                pids = subprocess.check_output(['pgrep',
                                                safe_process]).splitlines()
                running_process_ids[process] = pids
            except subprocess.CalledProcessError:
                # No results
                pass
        self.processes = running_process_ids


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


def main():
    """Manage arguments and coordinate our saving throw."""
    # Handle command line arguments.
    parser = build_argparser()
    args = parser.parse_args()

    if args.verbose:
        logger.verbose = True

    controller = AdwareController()
    for source in NEFARIOUS_FILE_SOURCES:
        controller.add_adware_from_url(source)

    # Which action should we perform? An EA has no arguments, so make
    # it the default.
    if args.remove:
        controller.remove()
        controller.kill()
    elif args.quarantine:
        controller.quarantine()
        controller.kill()
    elif args.stdout:
        controller.report_to_stdout()
    else:
        controller.extension_attribute()


if __name__ == '__main__':
    main()

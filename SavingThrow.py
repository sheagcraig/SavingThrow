#!/usr/bin/python
# Copyright (C) 2015 Shea G Craig
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
SavingThrow

Identify or remove files known to be involved in Adware infection,
based on curated lists of associated files.
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
from xml.etree import ElementTree
import zipfile
# zipfile needs zlib available to compress archives.
import zlib  # pylint: disable=unused-import


__version__ = '0.0.3'


# Add any URL's to nefarious file lists here:
NEFARIOUS_FILE_SOURCES = []

# Include Apple's identified Adware files by default.
# https://support.apple.com/en-us/ht203987
HT203987_URL = 'https://raw.githubusercontent.com/SavingThrows/AdwareDefinitionFiles/master/Apple-HT203987.adf'  # pylint: disable=line-too-long
NEFARIOUS_FILE_SOURCES.append(HT203987_URL)

CACHE = '/Library/Application Support/SavingThrow'


class Logger(object):
    """Simple logging class with shared verbosity state.."""

    verbose = False

    @classmethod
    def enable_verbose(cls):
        """Set all Loggers to verbose."""
        cls.verbose = True

    def log(self, message, log_level=syslog.LOG_ALERT):
        """Log to the syslog, and if verbose, also to stdout."""
        syslog.syslog(log_level, message)
        if self.verbose:
            print message

    @classmethod
    def vlog(cls, message, log_level=syslog.LOG_ALERT):
        """Log to the syslog and to stdout."""
        syslog.syslog(log_level, message)
        print message


class AdwareController(object):
    """Manages a group of Adware objects."""

    def __init__(self):
        """Create a controller"""
        self.adwares = []
        self.logger = Logger()

    def add_adware_from_url(self, source):
        """Given a URL to an adware description file, attempt to
        download, parse, and generate a set of targeted files and
        processes, and add to internal adwares list.

        """
        cache_file = os.path.basename(source)
        # Handle URLs which don't point at a specific file. e.g.
        # Permalinked gists can be referenced with a directory URL.
        if not cache_file:
            # Remove the protocol and swap slashes to periods.
            # Drop the final slash (period).
            cache_file = source.split("//")[1].replace("/", ".")[:-1]
        cache_path = os.path.join(CACHE, cache_file)

        self.logger.log("Attempting to update Adware list: %s" % source)
        try:
            adware_text = urllib2.urlopen(source).read()

            # Update our cached copy.
            try:
                with open(cache_path, 'w') as cache_file:
                    cache_file.write(adware_text)
            except IOError as error:
                if error[0] == 13:
                    print "Please run as root!"
                    sys.exit(13)
                else:
                    raise error

        except urllib2.URLError as error:
            # Use the cached copy if it exists.
            self.logger.log("Update failed: %s. Looking for cached copy" %
                            error.message)
            try:
                with open(cache_path, 'r') as cache_file:
                    adware_text = cache_file.read()
            except IOError as error:
                self.logger.log("Error: No cached copy of %s or other error %s"
                                % (source, error.message))

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
                for num, found in enumerate(adware.found, 1):
                    result += "File %s: %s\n" % (num, found)
                for num, found in enumerate(adware.processes.items(), 1):
                    pids_string = ', '.join((str(pid) for pid in found[1]))
                    result += "Process %s: %s PID: %s\n" % (num, found[0],
                                                            pids_string)

        return result

    def report_to_stdout(self):
        """Report back on identified files."""
        report_string = self.report_string()
        if report_string:
            result = 'Adware files and processes found:\n%s' % report_string
        else:
            result = 'No adware files or processes found.'

        Logger.vlog(result)

    def extension_attribute(self):
        """Report back on identified files in a Casper extension
        attribute format.
        """
        result = '<result>'
        report_string = self.report_string()
        if report_string:
            result += 'True\n%s' % report_string
        else:
            result += 'False'

        result += '</result>'
        Logger.vlog(result)

    def remove(self):
        """Delete identified files and directories."""
        files = [(afile, adware.name) for adware in self.adwares for afile in
                 adware.found]
        self.unload_and_disable_launchd_jobs([afile[0] for afile in files])
        for item, name in files:
            try:
                if os.path.isdir(item):
                    shutil.rmtree(item)
                elif os.path.isfile(item):
                    os.remove(item)
                self.logger.log('Removed adware file: %s:%s' % (name, item))
            except OSError as error:
                self.logger.log('Failed to remove adware file: %s:%s Error: '
                                '%s' % (name, item, error))

    def quarantine(self):
        """Move all identified files to a timestamped folder in our
        cache.
        """
        files = [(afile, adware.name) for adware in self.adwares for afile in
                 adware.found]
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        # Let's not bother if the list is empty.
        if files:
            quarantine_dir = os.path.join(CACHE, 'Quarantine')
            if not os.path.exists(quarantine_dir):
                os.mkdir(quarantine_dir)
            backup_dir = os.path.join(quarantine_dir, timestamp)
            os.mkdir(backup_dir)

            self.unload_and_disable_launchd_jobs([afile[0] for afile in files])

            for item, name in files:
                try:
                    shutil.move(item, backup_dir)
                    self.logger.log('Quarantined adware file: %s:%s'
                                    % (name, item))
                except OSError as error:
                    self.logger.log('Failed to quarantine adware file: %s:%s '
                                    'Error:  %s' % (name, item, error))

            zpath = os.path.join(quarantine_dir, "%s-Quarantine.zip" %
                                 timestamp)
            with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as zipf:
                os.chdir(backup_dir)
                for item in files:
                    zipf.write(os.path.basename(item[0]))

            self.logger.log("Zipped quarantined files to:  %s" % zpath)

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
        for afile in launchd_config_files:
            self.logger.log('Unloading %s' % afile)
            result = ''
            try:
                # Toss out any stderr messages about things not being
                # loaded. We just want them off; don't care if they're
                # not running to begin with.
                result = subprocess.check_output(['launchctl', 'unload', '-w',
                                                  afile],
                                                 stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as error:
                # Job may not be loaded, so just log and move on.
                result = error.message
            finally:
                if result:
                    self.logger.log('Launchctl response: %s' % result)

    def kill(self):
        """Given a list of running process ids, try to kill them."""
        kill_list = [pid for adware in self.adwares for process in
                     adware.processes.values() for pid in process]
        for process_id in kill_list:
            try:
                subprocess.check_call(['kill', str(process_id)])
                self.logger.log("Killed process ID: %s" % process_id)
            except subprocess.CalledProcessError:
                self.logger.log("Failed to kill process ID: %s" % process_id)


class Adware(object):
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
        """Identify files on the system that match this Adware."""
        logger = Logger()
        candidates = set()
        process_candidates = set()
        logger.log('Searching for files and processes defined in: %s'
                   % self.name)
        # First look for regex-confirmed files to prepare for text
        # replacement.
        for tested_file in self.xml.findall('TestedFile'):
            regex = re.compile(tested_file.findtext('Regex'))
            replacement_key = tested_file.findtext('ReplacementKey')
            fnames = glob.glob(tested_file.findtext('File'))
            for fname in fnames:
                with open(fname, 'r') as afile:
                    text = afile.read()

                if re.search(regex, text):
                    candidates.add(fname)

                    if replacement_key:
                        self.env[replacement_key] = re.search(regex,
                                                              text).group(1)

        # Now look for regular files.
        for std_file in self.xml.findall('File'):
            # Perform text replacments
            if "%" in std_file.text:
                for key in self.env:
                    std_file.text = std_file.text.replace("%%%s%%" % key,
                                                          self.env[key])
            candidates.add(std_file.text)

        # Find files on the drive.
        # OS X is case insensitive, so we have to test to avoid
        # including duplicates in the case *sensitive* set.
        matches = {match for filename in candidates for match in
                   glob.glob(filename)}
        self.found.update(matches)
        if matches:
            logger.log('Found files for: %s' % self.name)

        # Build a set of processes to look for.
        process_candidates = {process.text for process in
                              self.xml.findall('Process')}

        # Find running processes.
        self.get_running_process_ids(process_candidates)

    def get_running_process_ids(self, processes):
        """Given a list of process names, get running process ID's."""
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
        if running_process_ids:
            logger = Logger()
            logger.log('Found processes for: %s' % self.name)
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
    help_msg = ('Accepts all passed positional arguments (or none) to allow'
                'Casper script usage.')
    parser.add_argument('jamf-arguments', nargs='*', help=help_msg)
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
    # Ensure we have a cache directory.
    if not os.path.exists(CACHE):
        os.mkdir(CACHE)

    # Handle command line arguments.
    parser = build_argparser()
    args = parser.parse_args()

    # Configure verbose on logger Borg.
    logger = Logger()
    if args.verbose:
        logger.enable_verbose()

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

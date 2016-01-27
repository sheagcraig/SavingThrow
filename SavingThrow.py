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

Identify or remove files known to be involved with undesired apps,
based on curated lists of associated files.

usage: SavingThrow.py [-h] [-v] [-s | -r | -q]
                      [jamf-arguments [jamf-arguments ...]]

Modular Undesired file Extension Attribute and Removal Script. Call with
no arguments to run as an extension attribute, or with --remove or
--quarantine to operate as a cleanup tool.

positional arguments:
  jamf-arguments    Accepts all passed positional arguments (or none) to
                    allowCasper script usage.

optional arguments:
  -h, --help        show this help message and exit
  -v, --verbose     Print to stdout as well as syslog.
  -s, --stdout      Print standard report.
  -r, --remove      Remove offending files.
  -q, --quarantine  Move files to quarantine location.

Roll to save against paralyzation, lest the Gelatinous Cube anesthetizes,
and ultimately, digests you.
"""

# Historical Note
# SavingThrow was originally a tool for detecting and removing the
# software defined in Apple's KnowledgeBase article HT203987 located
# here: https://support.apple.com/en-us/ht203987
# As such, it's initial use was to specifically target and remove
# adware. However, as the idea of a community-sourced tool for
# detecting and removing apps based on collaborative research took off,
# SavingThrow grew beyond its initial target of Adware to include
# the ability to find and remove legitimate software as well.

# The software and documentation has been updated as best as possible
# without breaking compatibility with older behavior by naming things
# more appropriately and respectfully as "Apps" rather than "Adware".
# Ultimately, it is up to the person making use of this tool to decide
# what is wanted in their environment, and no judgement or slander is
# intentional or implied by the creator of this software.

# Wherever compatibility with older ADF format tag-names would break
# existing, but out-of-date installations of SavingThrow, the code will
# use the old names with the term "Adware", despite their inaccurate
# description of the range of software potentially targeted by users
# of this software.


# Import ALL the modules!
import argparse
from distutils.version import StrictVersion
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


__version__ = "1.1.0"


# Add any URLs to nefarious file lists
# format like this
# NEFARIOUS_FILE_SOURCES = ["https://blah.com/tacos.adf",
#                           "https://blah.com/more-tacos.adf"]

# Included for historical reasons: see note at top.
NEFARIOUS_FILE_SOURCES = []
ADF_FILE_SOURCES = []

# Include Apple's identified Adware files by default.
# https://support.apple.com/en-us/ht203987
HT203987_URL = "https://raw.githubusercontent.com/SavingThrows/AdwareDefinitionFiles/master/Apple-HT203987.adf"  # pylint: disable=line-too-long
NEFARIOUS_FILE_SOURCES.append(HT203987_URL)

ADF_FILE_SOURCES.extend(NEFARIOUS_FILE_SOURCES)

CACHE = "/Library/Application Support/SavingThrow"


class Logger(object):
    """Simple logging class with shared verbosity state."""

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


class FileController(object):
    """Manages a group of App objects.

    Atributes:
        apps: List of App objects to control.
        logger: Logger for handling output.
    """

    def __init__(self):
        """Initialize a new controller with its attributes."""
        self.apps = []
        self.logger = Logger()

    def add_app_from_url(self, source):
        """Add an App object to controller from a URL.

        Given an URL to an app description file, attempt to
        download, parse, and generate a set of targeted files and
        processes, and add to internal apps list.

        Args:
            source: String URL to an ADF file.

        Raises:
            All expected exceptions are handled.
        """
        cache_file = os.path.basename(source)
        # Handle URLs which don't point at a specific file. e.g.
        # Permalinked gists can be referenced with a directory URL.
        if not cache_file:
            # Remove the protocol and swap slashes to periods.
            # Drop the final slash (period).
            cache_file = source.split("//")[1].replace("/", ".")[:-1]
        cache_path = os.path.join(CACHE, cache_file)

        self.logger.log("Attempting to update App list: %s" % source)
        app_text = ""
        try:
            app_text = urllib2.urlopen(source).read()
        except urllib2.URLError as error:
            self.logger.log("Update failed: %s. Looking for cached copy" %
                            error.message)

        if app_text:
            # Update our cached copy.
            try:
                with open(cache_path, "w") as cache_file:
                    cache_file.write(app_text)
            except IOError as error:
                if error[0] == 13:
                    print "Please run as root!"
                    sys.exit(13)
                else:
                    raise error
        else:
            # Fallback to the cached file.
            try:
                with open(cache_path, "r") as cache_file:
                    app_text = cache_file.read()
            except IOError as error:
                self.logger.log("Error: No cached copy of %s or other error %s"
                                % (source, error.message))
        if app_text:
            try:
                adf_element = ElementTree.fromstring(app_text)
            except ElementTree.ParseError as err:
                logger = Logger()
                logger.log("ADF at %s is invalid XML (Error: %s)" %
                           (source, err.message))
                adf_element = None

            if adf_element is not None:
                self.warn_if_old_version(adf_element)
                self.apps.extend([App(app) for app in
                                     adf_element.findall("App")])
                # See historical note at top.
                self.apps.extend([App(app) for app in
                                     adf_element.findall("Adware")])

    def warn_if_old_version(self, adf_element):
        """Warn the user if the SavingThrow version is older than the ADF.

        An ADF file may optionally specify a minimum "SavingThrowVersion"
        which is needed for all features to work. The ADF may still work
        at reduced capacity.
        """
        min_version_elem = adf_element.find("SavingThrowVersion")
        logger = Logger()
        if min_version_elem is not None:
            min_version = StrictVersion(min_version_elem.text)
            if min_version > StrictVersion(__version__):
                app_names = ", ".join([name.findtext("AppName") for name
                                          in adf_element.findall("App")])
                adware_names = ", ".join([name.findtext("AdwareName") for name
                                          in adf_element.findall("Adware")])
                if adware_names:
                    app_names += ", %" % adware_names
                logger.log("%s require(s) SavingThrow version %s" %
                           (app_names, min_version))


    def report_string(self):
        """Generate a nicely formatted string of findings."""
        result = ""
        for app in self.apps:
            if app.found or app.processes:
                result += "Name: %s\n" % app.name
                for num, found in enumerate(app.found, 1):
                    result += "File %s: %s\n" % (num, found)
                for num, found in enumerate(app.processes.items(), 1):
                    pids_string = ", ".join((str(pid) for pid in found[1]))
                    result += "Process %s: %s PID: %s\n" % (num, found[0],
                                                            pids_string)

        return result

    def report_to_stdout(self):
        """Report back on identified files to STDOUT."""
        report_string = self.report_string()
        if report_string:
            result = "Files and processes found:\n%s" % report_string
        else:
            result = "No files or processes found."

        Logger.vlog(result)

    def extension_attribute(self):
        """Report back on found files in extension attribute format.

        For use with the Casper suite.

        Generates a report as XML and prints to STDOUT. Report is
        wrapped in <result> tags, with identified files numbered and
        ordered by App type.
        """
        result = "<result>"
        report_string = self.report_string()
        if report_string:
            result += "True\n%s" % report_string
        else:
            result += "False"

        result += "</result>"
        Logger.vlog(result)

    def remove(self):
        """Delete identified files and directories.

        Unloads launchd jobs, then removes all files and directories.

        If files are removed between App.find() and now, it will
        complain about missing files.

        Raises:
            Handles expected exceptions by logging.
        """
        files = [(afile, app.name) for app in self.apps for afile in
                 app.found]
        self.unload_and_disable_launchd_jobs([afile[0] for afile in files])
        for item, name in files:
            try:
                if os.path.isdir(item):
                    shutil.rmtree(item)
                elif os.path.isfile(item):
                    os.remove(item)
                self.logger.log("Removed file: %s:%s" % (name, item))
            except OSError as error:
                self.logger.log("Failed to remove file: %s:%s Error: "
                                "%s" % (name, item, error))

    def quarantine(self):
        """Quarantine files to a cache folder.

        Disables launchd jobs, then moves all files and directories
        to a Quarantine subfolder of the CACHE. Finally, a zip archive
        is produced, and files are deleted.

        If files are removed between App.find() and now, it will
        complain about missing files.

        Raises:
            Handles expected exceptions by logging.
        """
        files = [(afile, app.name) for app in self.apps for afile in
                 app.found]
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        # Let's not bother if the list is empty.
        if files:
            quarantine_dir = os.path.join(CACHE, "Quarantine")
            if not os.path.exists(quarantine_dir):
                os.mkdir(quarantine_dir)
            backup_dir = os.path.join(quarantine_dir, timestamp)
            os.mkdir(backup_dir)

            self.unload_and_disable_launchd_jobs([afile[0] for afile in files])

            for item, name in files:
                try:
                    shutil.move(item, backup_dir)
                    self.logger.log("Quarantined file: %s:%s"
                                    % (name, item))
                except shutil.Error:
                    # Raised when moving a directory, and it already
                    # exists.
                    counter = 1
                    success = False
                    while not success:
                        if counter > 10:
                            # Just give up.
                            break
                        try:
                            shutil.move(item, backup_dir + "/%s-%s" % (
                                os.path.basename(item), counter))
                            success = True
                        except shutil.Error:
                            counter += 1
                except OSError as error:
                    self.logger.log("Failed to quarantine file: %s:%s "
                                    "Error:  %s" % (name, item, error))

            zpath = os.path.join(quarantine_dir, "%s-Quarantine.zip" %
                                 timestamp)
            with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zipf:
                os.chdir(backup_dir)
                for item in files:
                    try:
                        zipf.write(os.path.basename(item[0].rstrip("/")))
                    except OSError:
                        pass

            self.logger.log("Zipped quarantined files to:  %s" % zpath)

            shutil.rmtree(backup_dir)

    def unload_and_disable_launchd_jobs(self, files):
        """Unload and disable launchd configuration files.

        Unloads launchd jobs with the -w flag to prevent jobs from
        respawning.

        Args:
            files: An iterable of file paths on the system. Method will
                handle determining which files are launchd config
                files.
        """
        # Find system-level LaunchD config files.
        conf_locs = {"/Library/LaunchAgents",
                     "/Library/LaunchDaemons",
                     "/System/Library/LaunchAgents",
                     "/System/Library/LaunchDaemons"}

        # Add valid per-user config locations.
        for user_home in os.listdir("/Users"):
            candidate_launchd_loc = os.path.join("/Users", user_home,
                                                 "Library/LaunchAgents")
            if os.path.exists(candidate_launchd_loc):
                conf_locs.add(candidate_launchd_loc)
        launchd_config_files = {file for file in files for conf_loc in
                                conf_locs if file.find(conf_loc) == 0}

        # Attempt to unload and disable these files.
        for afile in launchd_config_files:
            self.logger.log("Unloading %s" % afile)
            result = ""
            try:
                # Toss out any stderr messages about things not being
                # loaded. We just want them off; don't care if they're
                # not running to begin with.
                result = subprocess.check_output(
                    ["launchctl", "unload", "-w", afile],
                    stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as error:
                # Job may not be loaded, so just log and move on.
                result = error.message
            finally:
                if result:
                    self.logger.log("Launchctl response: %s" % result.strip())

    def kill(self):
        """Kill all processes found by controlled App(s)."""
        kill_list = [pid for app in self.apps for process in
                     app.processes.values() for pid in process]
        for process_id in kill_list:
            try:
                subprocess.check_call(["kill", str(process_id)])
                self.logger.log("Killed process ID: %s" % process_id)
            except subprocess.CalledProcessError:
                self.logger.log("Failed to kill process ID: %s" % process_id)


class App(object):
    """Represents one 'product', as defined in an App
    Definition File (ADF).

    Attributes:
        xml: The ADF as an xml.etree.Element.
        found: Set of files found on the current filesystem.
        processes: Dictionary of ProcessName: PIDs for currently
            running processes.
        name:
            String name of product from ADF/AppName.
    """

    def __init__(self, xml):
        """Init instance variables and find on current filesystem.

        Args:
            xml: root xml.etree.Element of an App Definition File.
        """
        self.xml = xml
        self._env = {}
        self.found = set()
        self.processes = {}
        # See historical note at top.
        self.name = (self.xml.findtext("AppName") or
                     self.xml.findtext("AdwareName"))

        self.find()

    def find(self):
        """Identify files and processes on the system."""
        logger = Logger()
        candidates = set()
        process_candidates = set()
        logger.log("Searching for files and processes defined in: %s"
                   % self.name)
        # First look for regex-confirmed files to prepare for text
        # replacement.
        for tested_file in self.xml.findall("TestedFile"):
            # Perform a glob and gather the results for all Path elements.
            paths = set()
            for path in tested_file.findall("Path"):
                for pattern in ("*", ".*"):
                    paths.update(set(glob.glob(os.path.join(path.text,
                                                            pattern))))

            # If provided, get and compile the regexes for filename
            # searching.
            fname_regexen = [fregex.text for fregex in
                             tested_file.findall("FilenameRegex")]
            compiled_fname_regexen = []
            if paths and fname_regexen:
                for fname_regex in fname_regexen:
                    try:
                        compiled_fname_regex = re.compile(fname_regex)
                        compiled_fname_regexen.append(compiled_fname_regex)
                    except re.error as re_error:
                        logger.log("Invalid regex: %s with error: %s in ADF "
                                   "for: %s" % (fname_regex, self.name,
                                                re_error.message))
                        continue
            elif paths and not fname_regex:
                logger.log("Paths supplied for %s, but no Regex provided. "
                           "Skipping this TestedFile." % self.name)
                continue

            # fnames collects full paths to files which match the
            # FilenameRegex and 'File' elements which glob, for later
            # content searching should it be specified.
            fnames = []
            for fname_search in paths:
                for compiled_fname_regex in compiled_fname_regexen:
                    if re.search(compiled_fname_regex, fname_search):
                        fnames.append(fname_search)

            # Perform a glob and gather the results for all File elements.
            globs = [glob.glob(fname.text) for fname in
                     tested_file.findall("File")]
            fnames.extend([item for glob_list in globs for item in glob_list])

            # Get the regex to search within a file for, if it exists.
            regexen = [regex.text for regex in tested_file.findall("Regex")]
            compiled_regexen = []
            if regexen:
                for regex in regexen:
                    try:
                        compiled_regex = re.compile(regex)
                        compiled_regexen.append(compiled_regex)
                    except re.error as re_error:
                        logger.log("Invalid regex: %s with error: %s in ADF "
                                   "for: %s" % (regex, self.name,
                                                re_error.message))
                        continue
                # Get the replacement key if one is provided.
                replacement_key = tested_file.findtext("ReplacementKey")

                for fname in fnames:
                    with open(fname, "r") as afile:
                        text = afile.read()

                    for compiled_regex in compiled_regexen:
                        if re.search(compiled_regex, text):
                            candidates.add(fname)

                            if replacement_key:
                                self._env[replacement_key] = re.search(
                                    regex, text).group(1)
            else:
                candidates.update(set(fnames))

        # Now look for regular files.
        for std_file in self.xml.findall("File"):
            # Perform text replacments
            if "%" in std_file.text:
                for key in self._env:
                    std_file.text = std_file.text.replace("%%%s%%" % key,
                                                          self._env[key])
            candidates.add(std_file.text)

        # Find files on the drive.
        matches = {match for filename in candidates for match in
                   glob.glob(filename)}
        self.found.update(matches)
        if matches:
            logger.log("Found files for: %s" % self.name)

        # Build a set of processes to look for.
        process_candidates = {process.text for process in
                              self.xml.findall("Process")}

        # Find running processes.
        self._get_running_process_ids(process_candidates)

    def _get_running_process_ids(self, processes):
        """Determine running process PIDs.

        Args:
            processes: Iterable of process names. These names should
                correspond to those seen in Bash ps/pgrep.
        """
        self.processes = {}
        for process in processes:
            safe_process = "^%s$" % re.escape(process)
            try:
                pids = subprocess.check_output(
                    ["pgrep", safe_process]).splitlines()
                self.processes[process] = pids
            except subprocess.CalledProcessError:
                # No results
                pass

        if self.processes:
            logger = Logger()
            logger.log("Found processes for: %s" % self.name)


def build_argparser():
    """Create our argument parser."""
    description = ("Modular Undesired file Extension Attribute and "
                   "Removal Script. Call with no arguments to run as "
                   "an extension attribute, or with --remove or "
                   "--quarantine to operate as a cleanup tool.")
    epilog = ("Roll to save against paralyzation, lest the Gelatinous "
              "Cube anesthetizes, and ultimately, digests you.")
    parser = argparse.ArgumentParser(description=description, epilog=epilog)
    help_msg = ("Accepts all passed positional arguments (or none) to allow"
                "Casper script usage.")
    parser.add_argument("jamf-arguments", nargs="*", help=help_msg)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print to stdout as well as syslog.")
    mode_parser = parser.add_mutually_exclusive_group()
    mode_parser.add_argument(
        "-s", "--stdout", help="Print standard report.", action="store_true")
    mode_parser.add_argument(
        "-r", "--remove", help="Remove files.", action="store_true")
    mode_parser.add_argument(
        "-q", "--quarantine", help="Move files to quarantine "
        "location.", action="store_true")

    return parser


def main():
    """Manage arguments and coordinate our saving throw."""
    # Ensure we have a cache directory.
    if not os.path.exists(CACHE):
        os.mkdir(CACHE)

    # Handle command line arguments.
    parser = build_argparser()
    # We use the parse_known_args method to avoid having to deal with
    # any empty arguments Casper may tack onto the end.
    args = parser.parse_known_args()[0]

    # Configure verbose on logger Borg.
    logger = Logger()
    if args.verbose:
        logger.enable_verbose()

    controller = FileController()
    for source in ADF_FILE_SOURCES:
        controller.add_app_from_url(source)

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


if __name__ == "__main__":
    main()

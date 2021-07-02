'''A class to validate and/or wrap calls to rsync'''

import re
import threading
import subprocess
from pathlib import Path
from shlex import quote
from urllib.parse import urlparse
from .error import DSConfigTargetError, DSConfigSyntaxError, \
        DSRsyncError, DSError


class DSRsync:
    '''Interact with validated rsync CLI commands'''

    # We need to validate rsync options.  This list was taken
    # from rsync version 3.1.3 protocol version 31. The CLI to get this
    # into a Python list syntax from the rsync client was:
    # rsync --help 2>&1 | \
    #  awk '{ if ( $1 ~ "--" || $2 ~ "--") {
    #           if ( $1 ~ /^--/ ) {print $1}
    #           else {print $2}}}' | \
    #  sed -e 's/^--//' -e 's/=.\+$//' -e "s/^/    '/" -e "s/$/',/" | \
    #  sort
    RSYNC_OPTIONS_VALID = {
        '8-bit-output': bool, 'acls': bool, 'address': str,
        'append': bool, 'append-verify': bool, 'archive': bool,
        'backup': bool, 'backup-dir': str, 'block-size': (int, str),
        'blocking-io': bool, 'bwlimit': (int, str), 'checksum': bool,
        'checksum-choice': str, 'checksum-seed': int,
        'chmod': (list, str), 'chown': str, 'compare-dest': str,
        'compress': bool, 'compress-level': int,
        'contimeout': (int, str), 'copy-dest': str,
        'copy-dirlinks': bool, 'copy-links': bool,
        'copy-unsafe-links': bool, 'cvs-exclude': bool, 'debug': str,
        'del': bool, 'delay-updates': bool, 'delete': bool,
        'delete-after': bool, 'delete-before': bool,
        'delete-delay': bool, 'delete-during': bool,
        'delete-excluded': bool, 'delete-missing-args': bool,
        'devices': bool, 'dirs': bool, 'dry-run': bool,
        'exclude': (list, str), 'exclude-from': str,
        'executability': bool, 'existing': bool, 'fake-super': bool,
        'files-from': str, 'filter': (list, str), 'force': bool,
        'from0': bool, 'fuzzy': bool, 'group': str, 'groupmap': str,
        'hard-links': bool, 'help': bool, 'human-readable': bool,
        'iconv': str, 'ignore-errors': bool, 'ignore-existing': bool,
        'ignore-non-existing': bool, 'ignore-missing-args': bool,
        'ignore-times': bool, 'include': (list, str),
        'include-from': str, 'info': str, 'inplace': bool,
        'ipv4': bool, 'ipv6': bool, 'itemize-changes': bool,
        'keep-dirlinks': bool, 'link-dest': (list, str), 'links': bool,
        'list-only': bool, 'log-file': str, 'log-file-format': str,
        'max-delete': int, 'max-size': (int, str),
        'min-size': (int, str), 'modify-window': int,
        'msgs2stderr': bool, 'munge-links': bool,
        'no-implied-dirs': bool, 'no-motd': bool, 'noatime': bool,
        'numeric-ids': bool, 'omit-dir-times': bool,
        'omit-link-times': bool, 'one-file-system': bool,
        'only-write-batch': str, 'out-format': str, 'outbuf': str,
        'owner': str, 'partial': bool, 'partial-dir': str,
        'password-file': str, 'perms': bool, 'port': int,
        'preallocate': bool, 'progress': bool, 'protect-args': bool,
        'protocol': int, 'prune-empty-dirs': bool, 'quiet': bool,
        'read-batch': str, 'recursive': bool, 'relative': bool,
        'remote-option': str, 'remove-source-files': bool, 'rsh': str,
        'rsync-path': str, 'safe-links': bool, 'size-only': bool,
        'skip-compress': str, 'sockopts': str, 'sparse': bool,
        'specials': bool, 'stats': bool, 'stop-at': str, 'suffix': str,
        'super': bool, 'temp-dir': str, 'time-limit': int,
        'timeout': (int, str), 'times': bool, 'update': bool,
        'usermap': str, 'verbose': bool, 'version': bool,
        'whole-file': bool, 'write-batch': str, 'xattrs': bool}

    # Add 'no-' options to our dict. Almost all long strings in rsync
    # can be prepended with 'no-' to negate implicit commands. We'll
    # simply create a --no-<key> for every key. This causes some
    # non-sensical options like --no-version to pass validation in
    # Python, however, since rsync will still generate an error at
    # runtime for those few edge cases, we'll tolerate the cheap hack.
    RSYNC_OPTIONS_VALID = {**RSYNC_OPTIONS_VALID,
                           **{'no-{0}'.format(k): v for k, v in
                              RSYNC_OPTIONS_VALID.items()}}

    RSYNC_RETURN_CODES = {
        0: 'Success',
        1: 'Syntax or usage error',
        2: 'Protocol incompatibility',
        3: 'Errors selecting input/output files, dirs',
        4: 'Requested action not supported: an attempt was made to ' +
           'manipulate 64-bit files on a platform that cannot ' +
           'support them; or an option was specified that is ' +
           'supported by the client and not by the server.',
        5: 'Error starting client-server protocol',
        6: 'Daemon unable to append to log-file',
        10: 'Error in socket I/O',
        11: 'Error in file I/O',
        12: 'Error in rsync protocol data stream',
        13: 'Errors with program diagnostics',
        14: 'Error in IPC code',
        20: 'Received SIGUSR1 or SIGINT',
        21: 'Some error returned by waitpid()',
        22: 'Error allocating core memory buffers',
        23: 'Partial transfer due to error',
        24: 'Partial transfer due to vanished source files',
        25: 'The --max-delete limit stopped deletions',
        30: 'Timeout in data send/receive',
        35: 'Timeout waiting for daemon connection'
    }

    def __init__(self):
        # Confirm rsync is installed by getting version/protocol
        self.version, self.protocol = self.rsync_version()

        # Set up an empty lists to track what subprocesses fail/succeed
        self.failed_codes = set()
        self.failed_jobs = []
        self.success_jobs = []

    def parse_rsyncopts(self, opts_dict, dry_run, debug, quiet, verbose,
                        shell=True):
        '''Convert a dict of rsync options to an array of rsync CLI
           options, verifying them against cached valid options from
           `man rsync`.'''
        opts_list = []

        if dry_run:
            opts_dict['dry-run'] = True

        # Override rsync verbosity, based on CLI args
        if debug or verbose:
            opts_dict['quiet'] = False
            opts_dict['stats'] = True
            opts_dict['verbose'] = True
        else:
            opts_dict['quiet'] = False  # want output in log file
            opts_dict['stats'] = True   # output should just be stats
            opts_dict['verbose'] = False

        # We want our command built with alphanumeric sorting, but
        # we do not want to disturb the ordering of list() items that
        # can be called multiple times, such as --filter, --include,
        # --exclude, which depend on specific ordering to affect
        # behavior. As such, sort dict_items, here, which orders the
        # arguments (EG --archive before --xattr), but does not alter
        # list() objects provided for keys
        for key, val in sorted(opts_dict.items()):
            try:
                if not isinstance(val, self.RSYNC_OPTIONS_VALID[key]):
                    raise DSConfigSyntaxError(
                        'rsync option "%s" requires data type %s.\n' % (
                            key, self.RSYNC_OPTIONS_VALID[key]))
            except KeyError:
                raise DSConfigSyntaxError(
                    'Unsupported rsync option "%s".\n' % key +
                    'Valid options are %s' %
                    ', '.join(self.RSYNC_OPTIONS_VALID.keys()))

            if isinstance(val, bool):
                # Ensure booleans are added or removed
                arg = '--%s' % key
                if val is True and arg not in opts_list:
                    opts_list.append(arg)
                elif val is False and arg in opts_list:
                    opts_list.remove(arg)
            elif isinstance(val, list):
                for i in val:
                    # Conditionally quote argument when shell is True
                    arg, shell = self.shellquote(i, shell)
                    opts_list.append('--%s=%s' % (key, arg))
            else:
                # Conditionally quote argument when shell is True
                arg, shell = self.shellquote(val, shell)
                arg = quote(str(val)) if shell else str(val)
                opts_list.append('--%s=%s' % (key, arg))

        return (opts_list, shell)

    @staticmethod
    def rsync_target(target):
        '''Determine if we got a valid rsync src or dst'''

        if not isinstance(target, str):
            raise DSConfigTargetError('rsync target %s must be a string' %
                                      target)

        # Not valid rsync URI syntax nor Path syntax
        if urlparse(target).scheme != 'rsync' and not \
                target.starts_with(Path(target).__str__()):
            raise DSConfigTargetError(
                'Unsupported rsync target "%s". Use URI or Path syntax' %
                target)

    def rsync_thread(self, command, shell=True, logger=None):
        '''Execute single rsync command via subprocess and return
           results the results.  This method is designed to be called
           using multithreading'''
        mythread = threading.current_thread()

        # Create string variant of command as needed
        cmdstr = command
        if isinstance(cmdstr, list):
            cmdstr = ' '.join(command)
        elif not isinstance(cmdstr, str):
            raise DSError('command for rsync must be list() or str()')

        if shell is False:
            cmd = command  # list not string, here
            mythread.name = mythread.name.replace('Thread', 'NoShell')
        else:
            mythread.name = mythread.name.replace('Thread', 'Shell')
            cmd = cmdstr   # string not list, here

        logstr = 'JOB: "%s" exited with return code %d. Output:\n%s'
        try:
            run = subprocess.run(cmd, check=True, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, shell=shell)
        except subprocess.CalledProcessError as err:
            # Raise an exception later; just warn for now.
            logger.warning(logstr, err.cmd, err.returncode,
                           err.stderr.decode())
            self.failed_jobs.append(err)
            self.failed_codes.add(self.RSYNC_RETURN_CODES[err.returncode])
        else:
            logger.info(logstr, run.args, run.returncode, run.stdout.decode())
            self.success_jobs.append(run)

    @staticmethod
    def rsync_version():
        '''Determine if rsync is available as a callable CLI command'''
        try:
            run = subprocess.run(('rsync', '--version'),
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 check=True)
        except subprocess.CalledProcessError as err:
            raise DSRsyncError('%s' % err)
        except FileNotFoundError as err:
            raise DSRsyncError('%s' % err)

        version = re.search(r"version\s+(\d+\.\d+\.\d+)",
                            run.stdout.decode("utf8")).groups()[0]
        if not isinstance(version, str):
            raise DSError(
                'rsync does not appear to be installed/available')

        # We need protocol too for potenial batch operations
        protocol = int(re.search(r"protocol\s+version\s+(\d+)",
                                 run.stdout.decode("utf8")).groups()[0])

        return (version, protocol)

    @staticmethod
    def shellquote(value, shell):
        '''Take in a string argment, ensure it is a string, quote as
           needed and turn on shell as needed'''
        if not isinstance(value, str):
            value = str(value)

        arg = quote(value)

        if arg != value:
            shell = True

        return (arg, shell)

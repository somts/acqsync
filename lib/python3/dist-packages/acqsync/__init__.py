'''Acqsync lib file

Build series of rsync CLI commands, then run them in parallel (but log
in series). This tool is used to sync data acquisition directories to
shared storage.

See -T argument for expected default YAML path. Expects a YAML file
formatted per .yaml files in EXAMPLES dir.
'''
# CHANGELOG:
# 2008    fmd   : Initial creation
# 2009-01 jmeyer: added error checking and ability to comment .acqsync, logging
# 2009-02 jmeyer: ported to Python, changed config name to .acqsync.tsv.
#                 Sorry it's so hacky.  Feel free to improve.
# 2009-02 ncohen: Refactoring.  De-hacky-izing.
# 2017-09 jmeyer: pylint, pass 1
# 2020-10 jmeyer: python2 -> python3
# 2020-11 jmeyer: PEP8/pylint cleanup, add basic parallelism
# 2021-06 jmeyer: Lotsa hackery.  Add .gitignore so that we can support
#                 .pyvenv. Enhance YAML options after deploying on
#                 ships. Allow jinja2 syntax in src/dst args. Use
#                 python to render date globs based on cruise metadata.
#                 Move Acqsync class to lib and make the executable a
#                 lightweight wrapper.

import argparse
import datetime
import logging
import logging.handlers
import os
import re
import subprocess
import sys
import time
from itertools import chain
from multiprocessing.dummy import Pool
from types import SimpleNamespace

from jinja2 import Template
import yaml

import acqsync.error


class Acqsync:
    '''Class for setting up an acqsync instance'''
    def __init__(self, cmdpath='/usr/bin/rsync'):
        self.logger = logging.getLogger('acqsync')
        self.cmds = []

        self.cmdpath = cmdpath

        # setup/defaults
        # rsyncopts may be overridden by YAML, later, but we will set
        # up sensible defaults.
        self.conf = SimpleNamespace(
            consolehandler=logging.StreamHandler(),
            rsyncopts=[
                '--archive',
                '--chmod=Dg+st,ugo+rx,Fo-w,+X'
                '--exclude=".Trash*/"',
                '--exclude="._*"',
                '--exclude=.DS_Store',
                '--exclude=.TemporaryItems/',
                '--exclude=Picasa.ini',
                '--exclude=Thumbs.db',
                '--no-g',
                '--no-p',
                '--one-file-system',
                '--timeout=60',
            ],
        )

        # Continue setup, potentially based on user input
        self.configure_args()

        # Set up rfhandler, based on derived logfilepath
        setattr(
            self.conf,
            'rfhandler',
            logging.handlers.RotatingFileHandler(
                self.conf.logfilepath,
                maxBytes=1000*1000,
                backupCount=4
            )
        )

        # With setup complete, configure our logger
        self.configure_logging()

        self.logger.info('Parsing targets file: %s', self.conf.targetsfilepath)
        self.parse_targets_file()

    def configure_logging(self):
        '''Configure logging object for use from acqsync'''

        # pass all messages down to handlers
        self.logger.setLevel(logging.DEBUG)

        # custom log formatter
        formatter = logging.Formatter(
            '[%(levelname)s] %(asctime)s %(lineno)d %(message)s')

        # RotatingFileHandler logger
        self.conf.rfhandler.setFormatter(formatter)
        self.conf.rfhandler.setLevel(logging.INFO)
        self.logger.addHandler(self.conf.rfhandler)

        # syslog logger -- commented out because it requires
        # editing /etc/syslog.conf
        #
        # syslogHandler = logging.handlers.SysLogHandler()
        # syslogHandler.setFormatter(formatter)
        # syslogHandler.setLevel(logging.ERROR)
        # self.logger.addHandler(syslogHandler)

        # console logger
        self.conf.consolehandler.setLevel(logging.INFO)
        self.conf.consolehandler.setFormatter(formatter)
        self.logger.addHandler(self.conf.consolehandler)

        # Tweak logger settings based on userland args
        if self.args.dry_run or self.args.debug:
            # Enable this script and rsync to be more chatty
            self.conf.rfhandler.setLevel(logging.DEBUG)
            self.conf.consolehandler.setLevel(logging.DEBUG)
            self.conf.rsyncopts.append('--verbose')

            if self.args.dry_run:
                # Do not actually execute rsync copying
                self.conf.rsyncopts.append('--dry-run')
        else:
            # default rsync verbosity: only print errors to console
            self.conf.rsyncopts.append('--quiet')

        # Disable STDOUT and avoid general cron noise if in quiet mode
        if self.args.quiet:
            self.logger.removeHandler(self.conf.consolehandler)

    def configure_args(self):
        '''parse STDIN, if any'''

        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            description='''
                Build and execute a series of CLI rsync commands
                in order to synchronize data from our
                Data Acquisition Systems (DAS) to a central server.'''
        )

        parser.add_argument(
            '-L', '--logfilepath',
            dest='logfilepath',
            default='/var/log/acqsync.log',
            type=str,
            help='log file to write to')
        parser.add_argument(
            '-P', '--pidfilepath',
            dest='pidfilepath',
            default='/var/run/acqsync.pid',
            type=str,
            help='PID file to track')
        parser.add_argument(
            '-T', '--targetsfilepath',
            dest='targetsfilepath',
            default='/share/cruise/CURRENT/.acqsync.yaml',
            type=str,
            help='targets file to read from')
        parser.add_argument(
            '-t', '--threadcount',
            dest='threadcount',
            default=16,
            type=int,
            help='number of parallel rsync jobs to run')

        agroup = parser.add_mutually_exclusive_group()
        agroup.add_argument(
            '-n', '--dry-run',
            action='store_true',
            dest='dry_run',
            help='Conduct a dry run. Sets verbosity debug.')
        agroup.add_argument(
            '-d', '--debug',
            action='store_true',
            dest='debug',
            help='Turn on debugging output.')
        agroup.add_argument(
            '-q', '--quiet',
            action='store_true',
            dest='quiet',
            help="No logging to STDOUT (EG for cron)")

        self.args = parser.parse_args()

        # Update conf with paths based on default or user input
        for i in ['logfilepath', 'pidfilepath', 'targetsfilepath']:
            setattr(self.conf, i, getattr(self.args, i))

    def parse_targets_file(self):
        '''Read our targets file for valid src/dst pairs

          See top of file for format example.
        '''
        try:
            with open(self.conf.targetsfilepath, 'rb') as cfg:
                myyaml = yaml.load(cfg, Loader=yaml.FullLoader)
        except IOError as err:
            raise acqsync.error.FatalError(
                'Cannot locate or open %s.' % self.conf.targetsfilepath, err)
        except ValueError as err:
            raise acqsync.error.ConfigFileSyntaxError(
                'Syntax error in targets file %s.' % self.conf.targetsfilepath,
                err)
        else:
            # YAML may override our default rsync path
            if 'path' in myyaml['config']['rsync']:
                self.conf.cmdpath = myyaml['config']['rsync']['path']
                self.logger.warning('rsync executable path set to %s, per %s.',
                                    self.conf.cmdpath,
                                    self.conf.targetsfilepath)
            # YAML may override our default rsync options
            if 'options' in myyaml['config']['rsync']:
                self.conf.rsyncopts = Acqsync._parse_rsyncopts(
                        myyaml['config']['rsync']['options'])
                self.logger.warning('rsync options set to %s, per %s.',
                                    self.conf.rsyncopts,
                                    self.conf.targetsfilepath)

            # Convert YAML to SimpleNamespaces. Process required keys
            for i in ['config', 'items']:
                try:
                    if i == 'config':  # Process subkeys in config
                        for j in ['cruise', 'rsync']:
                            if j == 'cruise':
                                setattr(self.conf, j,
                                        self._parse_cruise(myyaml[i][j]))
                            else:
                                setattr(self.conf, j,
                                        SimpleNamespace(**myyaml[i][j]))
                            self.logger.debug('%s config = %s',
                                              j, getattr(self.conf, j))
                    else:
                        setattr(self.conf, i, SimpleNamespace(**myyaml[i]))
                        self.logger.debug('%s config = %s',
                                          i, getattr(self.conf, i))
                except AttributeError as err:
                    raise acqsync.error.ConfigFileSyntaxError(
                        'root key "%s" is not defined in %s! Exit.' %
                        (i, self.conf.targetsfilepath), err)

            # Do not run if disabled
            if self.conf.cruise.sync_run is False:
                self.logger.info(
                    'Cruise sync_run is disabled in %s. Not an error. Exit.',
                    self.conf.targetsfilepath)
                sys.exit(0)

            for modulename, args in self.conf.items.__dict__.items():
                self.logger.debug(
                    'Processing item "%s"...', modulename)
                target = SimpleNamespace(**args)

                try:
                    if target.enabled is False:
                        self.logger.warning(
                            '%s set to disabled. Skipping.', modulename)
                        continue
                except AttributeError:
                    self.logger.debug(
                        '%s has no "enabled" parameter. Default enabled.',
                        modulename)

                # set module-specific rsync options
                try:
                    if not isinstance(target.rsync_options, dict):
                        raise acqsync.error.ConfigFileSyntaxError(
                            'rsync_options in module "%s" (%s) ' %
                            (modulename, self.conf.targetsfilepath) +
                            'must be type dict, got %s' %
                            type(target.rsync_options))
                except AttributeError:
                    target.rsync_options = {}

                # Run each module through Jinja2 templating engine
                srctemplate = Template(target.src)
                dsttemplate = Template(target.dst)
                target.src = srctemplate.render(
                    cruise=self.conf.cruise,
                    rsync_config=self.conf.rsync)
                target.dst = dsttemplate.render(
                    cruise=self.conf.cruise,
                    rsync_config=self.conf.rsync)

                # Attempt to make parent dir if it does not exist
                if not os.path.isdir(os.path.dirname(target.dst)):
                    self.logger.debug('Creating "%s"', target.dst)
                    os.makedirs(target.dst)

                self.logger.debug('rsync source argument: "%s"', target.src)
                self.logger.debug(
                    'rsync destination argument: "%s"', target.dst)

                # build cmd using list() + chain() in order to
                # create a flattened list. We then join on space specifically
                # because shell=True in subprocess (which requires this).
                cmd = ' '.join(list(chain(
                    [self.conf.rsync.path],
                    sorted(Acqsync._parse_rsyncopts(self.conf.rsync.options) +
                           Acqsync._parse_rsyncopts(target.rsync_options)),
                    [target.src, target.dst]
                )))
                # No need to log here as we will see this later
                # self.logger.debug('rsync constructed command: "%s"', cmd)
                self.cmds.append(cmd)
                self.logger.debug('Done')

    def check_singleton_process(self):
        '''check to see if we're already running. Quit if we are,
           'lock' if we aren't.'''

        self.logger.debug('Checking for previous pid file')
        if os.path.exists(self.conf.pidfilepath):
            self.logger.debug(
                'Found pidfile, checking for running process...')
            with open(self.conf.pidfilepath, 'r') as pidfile:
                try:
                    # read file and check to see if PID exists
                    pid = int(pidfile.read())
                    # kill -0 the pid to see if the PID exists
                    os.kill(pid, 0)
                    self.logger.exception(
                        'acqsync is already running, PID %d!', pid)
                    sys.exit(1)
                except (OSError, ValueError) as err:
                    self.logger.debug(err)
                    self.logger.warning(
                        '%s existed, but no running PID.',
                        self.conf.pidfilepath
                    )
                    self.logger.warning(
                        'Attempt cleanup of expired PID file, and proceed...'
                    )
                    # cleanup self.conf.pidfilepath and move on
                    os.remove(self.conf.pidfilepath)
                    self.logger.warning('Cleanup successful')

        # create pid file
        try:
            self.logger.debug('Creating PID file')
            with open(self.conf.pidfilepath, 'w') as pidfile:
                pidfile.write('%d' % os.getpid())
        except (IOError, PermissionError) as err:
            self.logger.error(
                'Could not create PID file: %s', self.conf.pidfilepath)
            self.logger.error(err)
            sys.exit(1)

    def cleanup_process(self):
        '''Clean up PID file'''
        try:
            self.logger.debug('Process exiting.  Attempting to cleanup')
            os.remove(self.conf.pidfilepath)
            self.logger.debug('Cleanup successful')
        except (IOError, PermissionError, OSError) as err:
            # cleanup failed, shouldn't get called
            self.logger.debug(err)
            self.logger.exception(
                'Cleanup failed: Could not remove PID file at exit')

    def execute_all_syncs(self):
        '''Determine if this is the only acqsync process running, then
           execute all configured syncs'''

        self.check_singleton_process()
        self.logger.info('Acqsync started')
        try:
            try:
                btime = time.perf_counter()
                self.logger.info(
                    'Starting up to %i parallel sync(s)...',
                    self.args.threadcount)

                # Execute subprocesses in parallel, but log the output
                # and/or errors in series. This allows humans to read
                # the logs but get datasets copied quicker.
                threads = Pool(self.args.threadcount)
                for cmd, stdout, stderr, retcode in \
                        threads.imap(Acqsync._subsync, self.cmds):

                    self.logger.info('Execution of rsync COMMAND (%s)...', cmd)
                    self.logger.debug('rsync STDOUT:')
                    self.logger.debug(stdout.decode())
                    if retcode == 0:
                        self.logger.info('SUCCESS')
                    else:
                        self.logger.warning('FAILURE: Return code %d\n%s',
                                            retcode, stderr.decode())

                self.logger.info('All syncs completed in %0.6f seconds',
                                 time.perf_counter() - btime)
            except acqsync.error.FatalError as err:
                self.logger.error(err)
        finally:
            self.cleanup_process()

    def _parse_cruise(self, cdict,
                      params=['begin', 'end', 'name', 'sync_run'],
                      pattern='^[A-Z]{2,3}([0-9]{4}|port)$'):
        '''confirm cruise metadata settings follow a certain schema'''
        keys = sorted(cdict.keys())

        # Confirm that we received only the cruise parameters we expect.
        if keys != params:
            self.logger.error(
                'Supported Cruise parameters are %s. Got %s',
                params, keys)
            sys.exit(10)

        for i in params:
            try:
                if i in ['begin', 'end']:
                    # Convert date to datetime.date type.
                    # Typically, ISO-style dates get automagically
                    # converted when the YAML is imported, but we
                    # ensure it, here.
                    if not isinstance(cdict[i], datetime.date):
                        cdict[i] = datetime.date('-'.split(cdict[i]))
                elif i == 'name':
                    # Ensure our cruise name matches a defined pattern
                    # EG RRport, HLY1234, SP4321
                    match = re.search(pattern, cdict[i])
                    if not match:
                        self.logger.error(
                            'Cruise name "%s" must match pattern "%s". Exit.',
                            cdict[i], pattern)
                        sys.exit(12)
                elif i == 'sync_run':
                    # Ensure sync_run is defined and a bool
                    if not isinstance(cdict[i], bool):
                        self.logger.error(
                            'Cruise sync_run must be defined and a boolean')
                        sys.exit(13)
            except KeyError:
                self.logger.error(
                    'Required cruise parameter "%s" is not defined. Exit.', i)
                sys.exit(11)

        return SimpleNamespace(**cdict)

    @staticmethod
    def _parse_rsyncopts(opts_dict):
        '''convert a dict of rsync options to an array of rsync CLI options'''
        opts_list = []

        for key, val in opts_dict.items():
            if isinstance(val, bool) and val is True:
                opts_list.append('--%s' % key)
            elif isinstance(val, list):
                for i in val:
                    opts_list.append('--%s="%s"' % (key, i))
            else:
                opts_list.append('--%s="%s"' % (key, val))

        return opts_list

    @staticmethod
    def _subsync(command):
        '''Execute single command via subprocess and return results'''

        with subprocess.Popen(command, shell=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as proc:
            stdout, stderr = proc.communicate()
            return_code = proc.poll()

            return command, stdout, stderr, return_code

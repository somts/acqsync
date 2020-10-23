#!/usr/bin/env python3

'''usage: %prog [options]

Sequentially rsync data acquisition directories to shared storage.
This script is driven by the contents of /mnt/cruise/CURRENT/.acqsync.conf,
consisting of source and dest rsync directory pairs, one/line.'''

# CHANGELOG:
# 2008    fmd   : Initial creation
# 2009-01 jmeyer: added error checking and ability to comment .acqsync, logging.
# 2009-02 jmeyer: ported to Python, changed config name to .acqsync.tsv.
#                 Sorry it's so hacky.  Feel free to improve.
# 2009-02 ncohen: Refactoring.  De-hacky-izing.
# 2017-09 jmeyer: pylint, pass 1
# 2020-10 jmeyer: python2 -> python3

import argparse
import logging
import logging.handlers
import os
import subprocess
import sys
from itertools import chain
from types import SimpleNamespace

import yaml

class FatalError(Exception):
    '''Hack our own fatal error class'''
    def __init__(self, errmsg, exception=None):
        self.errmsg = errmsg
        self.exception = exception

    def __str__(self):
        if self.exception:
            return ''.join(self.errmsg, '\n\t', str(self.exception))
        return self.errmsg

class ConfigFileSyntaxError(Exception):
    '''Hack our own fatal error class'''

class ConfigFileTargetError(FatalError):
    '''Hack our own fatal error class'''

class Acqsync:
    '''Class for setting up an acqsync instance'''
    def __init__(self):
        self.logger = logging.getLogger('acqsync')
        self.cmds = []

        # setup/defaults
        self.conf = SimpleNamespace(
            consolehandler=logging.StreamHandler(),
            rsyncopts=[
                '-a',
                '-x',
                '--no-p',
                '--no-g',
                '--exclude=.DS_Store',
                '--exclude=Thumbs.db',
                '--exclude=Picasa.ini',
                '--exclude="._*"',
                '--exclude=".Trash*/"',
                '--exclude=.TemporaryItems/',
                '--timeout=60',
                '--chmod=Dg+st,ugo+rx,Fo-w,+X'
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
        formatter = logging.Formatter('[%(levelname)s] %(asctime)s %(lineno)d %(message)s')

        # RotatingFileHandler logger
        self.conf.rfhandler.setFormatter(formatter)
        self.conf.rfhandler.setLevel(logging.INFO)
        self.logger.addHandler(self.conf.rfhandler)

        # syslog logger -- commented out because it requires editing /etc/syslog.conf
        #syslogHandler = logging.handlers.SysLogHandler()
        #syslogHandler.setFormatter(formatter)
        #syslogHandler.setLevel(logging.ERROR)
        #self.logger.addHandler(syslogHandler)

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
            default='/mnt/cruise/CURRENT/.acqsync.yaml',
            type=str,
            help='targets file to read from')

        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            '-n', '--dry-run',
            action='store_true',
            dest='dry_run',
            help='Conduct a dry run. Sets verbosity debug.')
        group.add_argument(
            '-d', '--debug',
            action='store_true',
            dest='debug',
            help='Turn on debugging output.')
        group.add_argument(
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

           Expects a YAML file with format like so:
           ---
           echodatafoo:
             src: rsync://echo-01.ucsd.edu/foo
             dst: /foo
           echodatabar:
             src: rsync://echo-01.ucsd.edu/bar
             dst: /bar
           metdata:
             src: rsync://met.ucsd.edu/data
             dst: /data
           ...
        '''
        try:
            with open(self.conf.targetsfilepath, 'rb') as cfg:
                myyaml = yaml.load(cfg, Loader=yaml.FullLoader)

                for modulename, args in myyaml.items():
                    self.logger.debug('Working on YAML module "%s"', modulename)
                    target = SimpleNamespace(**args)

                    # Attempt to make parent dir if it does not exist
                    if not os.path.isdir(os.path.dirname(target.dst)):
                        self.logger.debug('Creating "%s"', target.dst)
                        os.makedirs(target.dst)

                    self.logger.debug('rsync source argument: "%s"', target.src)
                    self.logger.debug('rsync destination argument: "%s"', target.dst)

                    # build cmd using list() + chain() to create a flattened list
                    cmd = list(chain(
                        ['/usr/bin/rsync'],
                        self.conf.rsyncopts,
                        [target.src, target.dst]
                    ))
                    self.logger.debug('rsync constructed command: "%s"', cmd)
                    self.cmds.append(cmd)
                    self.logger.debug('Done')
        except IOError as err:
            errmsg = 'Cannot locate or open %s.' % self.conf.targetsfilepath
            raise FatalError(errmsg, err)
        except ValueError as err:
            errmsg = 'Syntax error in targets file %s.' % self.conf.targetsfilepath
            raise FatalError(errmsg, err)

    def check_singleton_process(self):
        '''check to see if we're already running. Quit if we are,
           'lock' if we aren't.'''

        self.logger.debug('Checking for previous pid file')
        if os.path.exists(self.conf.pidfilepath):
            self.logger.debug('Found pidfile from previous run, checking for running process')
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
                        'Attempting to cleanup expired PID file, and proceeding.'
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
            self.logger.error('Could not create PID file: %s', self.conf.pidfilepath)
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
            self.logger.exception('Cleanup failed: Could not remove PID file at exit')

    def execute_all_syncs(self):
        '''Determine if this is the only acqsync process running, then
           execute all configured syncs'''

        self.check_singleton_process()
        self.logger.info('Acqsync started')
        try:
            try:
                self.logger.info('Starting sync(s)')

                for cmd in self.cmds:
                    self.execute_sync(cmd)
                self.logger.info('All syncs completed normally')
            except FatalError as err:
                self.logger.error(err.errmsg)
        finally:
            self.cleanup_process()

    def execute_sync(self, cmd):
        '''Execute single rsync job'''

        self.logger.info('BEGIN %s', ' '.join(cmd))

        # execute cmd, log
        with subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        ) as proc:
            stdout, stderr = proc.communicate()
            retcode = proc.poll()

        self.logger.debug('rsync STDOUT:')
        self.logger.debug(stdout)

        if retcode == 0:
            self.logger.info('SUCCESS')
        else:
            self.logger.warning('FAILURE: Return code %d\n%s', retcode, stderr)

def main():
    '''entry point when run from commandline'''
    acqsync = Acqsync()
    acqsync.execute_all_syncs()
    sys.exit(0)

if __name__ == "__main__":
    main()

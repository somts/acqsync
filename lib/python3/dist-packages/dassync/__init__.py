'''Data Acquistion System Sync (DASSync) lib file

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
#                 lightweight wrapper. Make dedicated config class.
#                 Add some class globals from `man rsync` like error
#                 codes and valid arguments.

import os
import subprocess
import sys
import threading
import time
from multiprocessing.dummy import Pool
from .config import DSConfig
from .error import FatalError


class DASSync:
    '''Execute N rsync jobs and report on what happened'''

    RSYNC_RETURN_CODES = {
      0: 'Success',
      1: 'Syntax or usage error',
      2: 'Protocol incompatibility',
      3: 'Errors selecting input/output files, dirs',
      4: '''Requested action not supported: an attempt was made to
            manipulate 64-bit files on a platform that cannot support
            them; or an option was specified that is supported
            by the client and not by the server.''',
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
        '''Configuration can be complex so we do our setup in a
           dedicated class.'''
        self.conf = DSConfig()

        # Set up an empty lists to track what subprocesses fail/succeed
        self.failed_codes = set()
        self.failed_jobs = []
        self.success_jobs = []

    def check_pid(self):
        '''check to see if we're already running. Quit if we are,
           'lock' if we aren't.'''
        pid = os.getpid()

        self.conf.logger.debug('Checking for PID file %s against PID %d',
                               self.conf.paths.pidfile, pid)
        if os.path.exists(self.conf.paths.pidfile):
            self.conf.logger.debug(
                'Found pidfile, checking for running process...')
            with open(self.conf.paths.pidfile, 'r') as pidfile:
                try:
                    # read file and check to see if PID exists
                    oldpid = int(pidfile.read())
                    # kill -0 the pid to see if the PID exists
                    os.kill(oldpid, 0)
                    self.conf.logger.exception(
                        'acqsync is already running, PID %d!', oldpid)
                    sys.exit(1)
                except (OSError, ValueError) as err:
                    self.conf.logger.warning(
                        '%s existed, but no running PID. %s',
                        self.conf.paths.pidfile,
                        'Attempt cleanup of expired PID file, and proceed...'
                    )
                    self.conf.logger.debug(err)

                    # cleanup self.conf.paths.pidfile and move on
                    os.remove(self.conf.paths.pidfile)
                    self.conf.logger.warning('Cleanup successful')

        try:  # create pid file
            with open(self.conf.paths.pidfile, 'w') as pidfile:
                self.conf.logger.debug('Creating PID file: %s (PID %d)',
                                       self.conf.paths.pidfile, pid)
                pidfile.write('%d' % pid)
                self.conf.logger.info('PID file %s "locked" by PID %d',
                                      self.conf.paths.pidfile, pid)
        except (IOError, PermissionError) as err:
            self.conf.logger.exception('Could not create PID file: %s. %s',
                                       self.conf.paths.pidfile, err)
            sys.exit(2)

    def cleanup_pid(self):
        '''Clean up PID file'''
        try:
            self.conf.logger.debug('Process exiting.  Attempting to cleanup')
            os.remove(self.conf.paths.pidfile)
            self.conf.logger.debug('Cleanup successful')
        except (IOError, PermissionError, OSError) as err:
            # cleanup failed, shouldn't get called
            self.conf.logger.debug(err)
            self.conf.logger.exception(
                'Cleanup failed: Could not remove PID file at exit')

    def run_syncs(self):
        '''Determine if this is the only acqsync process running, then
           execute all configured syncs'''

        self.check_pid()
        self.conf.logger.info('DASSync started')
        try:
            try:
                # Execute subprocesses in parallel, but log the output
                # and/or errors in series. This allows humans to read
                # the logs but get datasets copied quicker.
                btime = time.perf_counter()
                with Pool(processes=self.conf.threadcount) as pool:
                    self.conf.logger.info(
                        'Starting up to %i parallel sync(s)...',
                        self.conf.threadcount)
                    try:
                        pool.starmap(self.subsync, self.conf.jobs)
                    finally:
                        pool.close()  # no more jobs allowed
                        pool.join()   # wait for all jobs to complete

                self.success_jobs.sort()
                self.failed_jobs.sort()

                # Calculate how we did
                timelen = time.perf_counter() - btime
                failcount = len(self.failed_jobs)
                successcount = len(self.success_jobs)
                logstr = \
                    '%d syncs ran in %0.3f seconds (%d fail, %d success)' % (
                        len(self.conf.jobs), timelen, failcount, successcount)

                self.conf.logger.debug('Success jobs:\n\t%s',
                                       '\n\t'.join(self.success_jobs))

                # Log how we did. Some conditional logic bits, here.
                # Logging to CRITICAL will generate output in quiet
                # mode (EG cron) which can often generate email. So, we
                # conditionally raise an exception when we want this
                # (per CLI args). Otherwise, we just log to INFO.
                if failcount > 0:
                    logstr += ' Failed jobs:\n\t%s' % \
                            '\n\t'.join(self.failed_jobs)
                    if self.conf.critical_subprocess:
                        raise FatalError(logstr)

                if self.conf.critical_time != 0 and \
                        self.conf.critical_time < timelen:
                    logstr += ' This is over %d seconds of time.' % \
                        self.conf.critical_time
                    logstr += ' There may be syncronization delays if'
                    logstr += ' your crontab is set to run more frequently.'
                    raise FatalError(logstr)

                if failcount > 0:
                    self.conf.logger.warning(logstr)
                else:
                    self.conf.logger.info(logstr)

                # Lastly, note discrete failure codes received
                if len(self.failed_codes) > 0:
                    self.conf.logger.error('Rsync failure codes:\n\t%s',
                                           '\n\t'.join(self.failed_codes))

            except FatalError as err:
                self.conf.logger.critical(err)
        finally:
            self.cleanup_pid()

    def subsync(self, command, shell=True):
        '''Execute single command via subprocess and return results'''

        # Update threadName from (EG) Thread-1 to rsync-1
        mythread = threading.current_thread()

        # Create string variant of command as needed
        cmdstr = command
        if isinstance(cmdstr, list):
            cmdstr = ' '.join(command)

        if shell is False:
            cmd = command  # list not string, here
            mythread.name = mythread.name.replace('Thread', 'NoShell')
        else:
            mythread.name = mythread.name.replace('Thread', 'Shell')
            cmd = cmdstr   # string not list, here

        self.conf.logger.debug('rsync COMMAND: %s...', cmdstr)
        with subprocess.Popen(cmd,
                              shell=shell,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as proc:
            stdout, stderr = proc.communicate()
            retcode = proc.poll()

            self.conf.logger.debug('rsync STDOUT: %s', stdout.decode())
            self.conf.logger.debug('rsync return code %d: %s',
                                   retcode, self.RSYNC_RETURN_CODES[retcode])
            if retcode == 0:
                self.success_jobs.append(cmdstr)
            else:
                # Raise an exception later; just warn for now.
                self.failed_jobs.append(cmdstr)
                self.failed_codes.add(self.RSYNC_RETURN_CODES[retcode])

            return command, stdout, stderr, retcode

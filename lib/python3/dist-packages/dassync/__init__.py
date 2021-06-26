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
import sys
import time
from multiprocessing.dummy import Pool
from .config import DSConfig
from .error import DSError, DSRsyncError


class DASSync:
    '''Execute N rsync jobs and report on what happened'''

    def __init__(self):
        '''Configuration can be complex so we do our setup in a
           dedicated class.'''
        self.conf = DSConfig()
        self.rsync = self.conf.dsrsync
        self.pid = os.getpid()

    def check_pid(self):
        '''check to see if we're already running. Quit if we are,
           'lock' if we aren't.'''

        self.conf.logger.debug('Checking for PID file %s against PID %d',
                               self.conf.paths.pid, self.pid)
        if os.path.exists(self.conf.paths.pid):
            self.conf.logger.debug(
                'Found PID file (%s); checking for running process...',
                self.conf.paths.pid)
            with open(self.conf.paths.pid, 'r') as pidfile:
                try:
                    # read file and check to see if PID exists
                    oldpid = int(pidfile.read())
                    # kill -0 the pid to see if the PID exists
                    os.kill(oldpid, 0)
                    self.conf.logger.exception(
                        'PID %d is already running and has acqsync "locked"!',
                        oldpid)
                    sys.exit(1)
                except (OSError, ValueError) as err:
                    self.conf.logger.warning(
                        '%s exists, but no running PID. %s',
                        self.conf.paths.pid,
                        'Attempt cleanup of expired PID file...'
                    )
                    self.conf.logger.debug(err)

                    # cleanup self.conf.paths.pid and move on
                    try:
                        os.remove(self.conf.paths.pid)
                    except (IOError, PermissionError) as err:
                        self.conf.logger.fatal(
                            'Could not remove PID file: %s. %s',
                            self.conf.paths.pid, err)
                        sys.exit(2)
                    else:
                        self.conf.logger.warning('Cleanup successful')

        try:  # create pid file
            with open(self.conf.paths.pid, 'w') as pidfile:
                self.conf.logger.debug('PID %d is creating PID file %s',
                                       self.pid, self.conf.paths.pid)
                pidfile.write('%d' % self.pid)
                self.conf.logger.info('PID %d has "locked" acqsync (%s)',
                                      self.pid, self.conf.paths.pid)
        except (IOError, PermissionError) as err:
            self.conf.logger.fatal('Could not create PID file: %s. %s',
                                   self.conf.paths.pid, err)
            sys.exit(3)

    def clean_pid(self):
        '''Clean up PID file'''
        try:
            self.conf.logger.info(
                'PID %d is exiting. Attempting to cleanup %s',
                self.pid, self.conf.paths.pid)
            os.remove(self.conf.paths.pid)
            self.conf.logger.info('PID %d cleanup successful. Exit', self.pid)
        except (IOError, PermissionError, OSError) as err:
            # cleanup failed, shouldn't get called
            self.conf.logger.debug(err)
            self.conf.logger.exception(
                'Cleanup failed: Could not remove PID file %s at exit',
                self.conf.paths.pid)

    def log_built_jobs(self):
        '''Output all rendered job info to our logger'''
        ejobs = [' '.join(x[0]) for x in self.conf.enabled_jobs]
        djobs = [' '.join(x[0]) for x in self.conf.disabled_jobs]
        self.conf.logger.warning(
            "\n\n".join(['Build-only mode. No rsync execution.',
                         'Rendered %d total jobs, %d enabled, %d disabled',
                         'ENABLED JOBS:\n\n%s', 'DISABLED JOBS:\n\n%s']),
            len(ejobs+djobs), len(ejobs), len(djobs),
            "\n\n".join(ejobs), "\n\n".join(djobs))

    def log_disabled(self):
        '''Output all rendered job info to our logger'''
        self.conf.logger.warning(
            'Cruise sync_run is disabled in %s. Not an error. Exit.',
            self.conf.yamlpath)

    def log_syncs(self, timelen):
        '''Calculate/log the results of run_syncs()'''
        failcount = len(self.rsync.failed_jobs)
        successcount = len(self.rsync.success_jobs)

        # Log how we did. Some conditional logic bits, here.
        # Logging to CRITICAL will generate output in quiet
        # mode (EG cron) which can often generate email. So, we
        # conditionally raise an exception when we want this
        # (per CLI args). Otherwise, we just log to INFO.
        if successcount == 0:
            self.conf.logger.warning('SUCCESS JOBS count is zero!')

        if failcount > 0:
            self.conf.logger.warning('FAILED JOBS count is greater than zero!')
            if self.conf.critical_subprocess:
                raise DSRsyncError('FAILED JOB COUNT: %d' % failcount)

        logstr = \
            '%d syncs ran in %0.3f seconds (%d fail, %d success)' % (
                len(self.conf.enabled_jobs), timelen, failcount,
                successcount)

        if self.conf.critical_time != 0 and \
                self.conf.critical_time < timelen:
            logstr += ' This is over %d seconds of time.' % \
                self.conf.critical_time
            logstr += ' There may be syncronization delays if'
            logstr += ' your crontab is set to run more frequently.'
            raise DSError(logstr)

        if failcount > 0:
            self.conf.logger.warning(logstr)
        else:
            self.conf.logger.info(logstr)

        # Lastly, note discrete failure codes received
        if len(self.rsync.failed_codes) > 0:
            self.conf.logger.error('Rsync failure codes:\n\t%s',
                                   '\n\t'.join(
                                       self.rsync.failed_codes))

    def prepare_dirs(self):
        '''Create target directories as possible'''

        # Sort our set so that we make parents before children
        for i in sorted(self.conf.makedirs):
            if not i.is_dir():
                if self.conf.dry_run:
                    logstr = 'Would have created %s'
                else:
                    try:
                        i.mkdir(parents=True)
                    except (IOError, PermissionError) as err:
                        self.conf.logger.fatal(
                            'Could not create %s! Quit.\n%s', i, err)
                        sys.exit(3)
                    else:
                        logstr = 'Created %s'
                self.conf.logger.info(logstr, i.__str__())

    def run_syncs(self):
        '''Determine if this is the only acqsync process running, then
           execute all configured syncs'''
        btime = time.perf_counter()

        try:
            self.check_pid()     # "lock" with PID file
            self.prepare_dirs()  # prepare any missing directories we can
            self.conf.logger.info('DASSync started')

            # Execute subprocesses in parallel, but log the output
            # and/or errors in series. This allows humans to read
            # the logs but get datasets copied quicker.
            with Pool(processes=self.conf.threadcount) as pool:
                jlen = len(self.conf.enabled_jobs)
                self.conf.logger.info(
                    '%d jobs enabled. Will run %d sync(s) at a time...',
                    jlen, min(jlen, self.conf.threadcount))
                try:
                    # Copy our logger instances to every job
                    pool.starmap(
                        self.rsync.rsync_thread,
                        [list(x) + [self.conf.logger] for x in
                            self.conf.enabled_jobs])
                finally:
                    pool.close()  # no more jobs allowed
                    pool.join()   # wait for all jobs to complete

            self.log_syncs(time.perf_counter() - btime)
        except KeyboardInterrupt:
            self.conf.logger.warning('Quit on keyboard interupt')
        except DSRsyncError as err:
            self.conf.logger.critical(err)
        finally:
            self.clean_pid()

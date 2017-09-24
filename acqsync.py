#!/usr/bin/env python

"""usage: %prog [options]

Sequentially rsync data acquisition directories to shared storage.
This script is driven by the contents of /mnt/cruise/CURRENT/.acqsync.conf,
consisting of source and dest rsync directory pairs, one/line."""

#
# CHANGELOG:
# 2008   Delahoyde: Initial creation
# 2009-01 Meyer: added error checking and ability to comment .acqsync, logging.
# 2009-02 Meyer: ported to Python, changed config name to .acqsync.tsv.
#                Sorry it's so hacky.  Feel free to improve.
# 2009-02 Cohen: Refactoring.  De-hacky-izing.

import getopt,logging,logging.handlers,os,subprocess,sys,shlex,pprint

# get a global reference to a logging object for this portion of the app
logger = logging.getLogger('acqsync')

def configureLogging():
	"""Configure logging object for use from acqsync"""
	logger = logging.getLogger("acqsync")

	# pass all messages down to handlers
	logger.setLevel(logging.DEBUG)

	# custom log formatter
	formatter = logging.Formatter("[%(levelname)s] %(asctime)s %(lineno)d %(message)s")

	# RotatingFileHandler logger
	conf.rfHandler = logging.handlers.RotatingFileHandler(conf.logFilePath, maxBytes=1000*1000, backupCount=4)
	conf.rfHandler.setFormatter(formatter)
	conf.rfHandler.setLevel(logging.INFO)
	logger.addHandler(conf.rfHandler)

	# syslog logger -- commented out because it requires editing /etc/syslog.conf - lame
	#syslogHandler = logging.handlers.SysLogHandler()
	#syslogHandler.setFormatter(formatter)
	#syslogHandler.setLevel(logging.ERROR)
	#logger.addHandler(syslogHandler)

	# console logger
	conf.consoleHandler = logging.StreamHandler()
	conf.consoleHandler.setLevel(logging.INFO)
	conf.consoleHandler.setFormatter(formatter)
	logger.addHandler(conf.consoleHandler)


# helper class -- dictionary whose items can be accessed as attributes (ie foo['a'] == foo.a)
class AttrDict(dict):
	__getattr__= dict.__getitem__
	__setattr__= dict.__setitem__
	__delattr__= dict.__delitem__

conf = AttrDict(
	# setup/defaults
	pidFilePath='/var/run/acqsync.pid',
	targetsFilePath='/mnt/cruise/CURRENT/.acqsync.conf',
	logFilePath='/var/log/acqsync.log',
	rsyncopts = ['-axuv',
		     '--no-p',
		     '--no-g',
		     '--chmod=Dg+st,ugo+rx,Fo-w,+X',
		     ]
#		     '--timeout=60',
#		     '--exclude=.DS_Store',
#		     '--exclude=Thumbs.db',
#		     '--exclude=Picasa.ini',
#		     '--exclude="._*"',
#		     '--exclude=".Trash*/"',
#		     '--exclude=.TemporaryItems/',
#		     '--bwlimit=6400',
	)

class FatalError(Exception):
	def __init__(self, errmsg, exception=None):
		self.errmsg = errmsg
		self.exception = exception

	def __str__(self):
		if exception:
			return ''.join(errmsg, '\n\t', str(exception))
		return self.errmsg

class ConfigFileSyntaxError(Exception):
	pass

class ConfigFileTargetError(FatalError):
	pass

def parseTargetsFile(targetsFilePath=conf.targetsFilePath):
	try:
		cfg = open(targetsFilePath, "rb")
		try:
			targets = []
			for linenum, line in enumerate(cfg):
				target = shlex.split(line)

				if line.startswith('#') or len(target) == 0:
					continue
				if len(target) != 2:
					errmsg = "SyntaxError in targets file %s on line: %d\n\t2 paths per line required, found %d" % (targetsFilePath, linenum+1, len(target))
					raise ConfigFileSyntaxError(errmsg)

				# error if dst does not exist
				src,dst = target
				if not os.path.isdir(os.path.dirname(dst)):
					os.makedirs(dst)
#					errmsg = "Error in targets file %s on line: %d\n\tDestination directory %s does not exist." % (targetsFilePath, linenum+1, dst)
#					raise ConfigFileTargetError(errmsg)
				targets.append(target)
			logger.debug(targets)
			return targets
		finally:
			cfg.close()
	except IOError, e:
		errmsg = "Cannot locate or open %s." % ( targetsFilePath )
		raise FatalError(errmsg, e)
	except ValueError, e:
		errmsg = "Syntax error in targets file %s on line %s" % (targetsFilePath, linenum)
		raise FatalError(errmsg, e)

def check_singleton_process():
	# check to see if we're already running. Quit if we are, 'lock' if we aren't.
	pidFilePath = conf.pidFilePath

	logger.debug("Checking for previous pid file")
	if os.path.exists(pidFilePath):
		logger.debug("Found pidfile from previous run, checking for running process")
		pidFile = open(pidFilePath,"r")
		try:
			try:
				# read file and check to see if PID exists
				pid = int(pidFile.read())
				# kill -0 the pid to see if the PID exists
				os.kill(pid, 0)
				logger.exception("acqsync is already running, PID %d!" % (pid))
				sys.exit(1)
			except (OSError, ValueError), err:
				logger.warning(pidFilePath + " existed, but no running PID.  Attempting to cleaup expired PID file, and proceeding.")
				# cleanup pidFilePath and move on
				os.remove(pidFilePath)
				logger.warning( "Cleanup successful" )
		finally:
			pidFile.close()

	# create pid file
	try:
		try:
			logger.debug("Creating PID file")
			pidfile = open(pidFilePath, 'w')
			pidfile.write("%d" % os.getpid())
		finally:
			pidfile.close()
	except IOError,e:
		logger.error("Could not create PID file: %s" %pidFilePath)
		sys.exit(1)

def cleanup_process():
	try:
		logger.debug("Process exiting.  Attempting to cleanup")
		os.remove(conf.pidFilePath)
		logger.debug("Cleanup successful")
	except OSError, err:
		# cleanup failed, shouldn't get called
		logger.exception("Cleanup failed: Could not remove PID file at exit")

def executeSync(src, dst, rsyncopts):
	logger.info("BEGIN %s -> %s" % (src,dst))

	# build cmd
	cmd = [ '/usr/bin/rsync' ]
	cmd += rsyncopts
	cmd.append( src )
	cmd.append( dst )

	logger.debug("executing rsync command: %s" % repr(cmd))
	
	# execute cmd, log
	proc = subprocess.Popen( cmd,
				 stdout=subprocess.PIPE,
				 stderr=subprocess.PIPE
				 )
	stdout,stderr = proc.communicate()
	retcode = proc.poll()

	logger.debug("Showing rsync output:\n"+ stdout)
	
	if retcode == 0:
		logger.info("SUCCESS: %s -> %s" % (src,dst))
	else:
		logger.warning("FAILURE: Return code %d\n%s" % (retcode,stderr))

# entry point when run from commandline
def main():
	configureLogging()
	
	# shorter name for conf object
	d = conf

	# parse STDIN, if any
	from optparse import OptionParser
	parser = OptionParser(usage=__doc__)
	parser.add_option("-d", "--debug",  action="store_true", dest='debug', help="Turn on debugging output.")
	parser.add_option("-s", "--silent", action="store_true", dest="silent", help="Don't output anything to the console (for running from cron)")

	options, args = parser.parse_args()

	if options.debug:
		conf.rfHandler.setLevel(logging.DEBUG)
		conf.consoleHandler.setLevel(logging.DEBUG)
		rsyncVerbosity = "-v"
	else:
		# default verbosity only print errors to console
		conf.consoleHandler.setLevel(logging.INFO)
		rsyncVerbosity="-q"

	if options.silent:
		# don't intentionally output anything to console so cron will never squack (unless there really is a problem)
		rsyncVerbosity="-q"
		logger.removeHandler(conf.consoleHandler)

	conf.rsyncopts.append(rsyncVerbosity)
	
	check_singleton_process()

	logger.info("Acqsync started")
	
	try:
		try:
			rsyncopts = conf.rsyncopts
			logger.info("Parsing targets file: %s" %d.targetsFilePath)
			targets = parseTargetsFile(d.targetsFilePath)
			logger.info( "Starting sync(s)" )

			for row in targets:
				src, dst = row
				executeSync(src, dst, rsyncopts)
			logger.info( "All syncs completed normally" )
		except FatalError, e:
			logger.error(e.errmsg)
	finally:
		cleanup_process()

	sys.exit(0)

if __name__ == "__main__":
	main()

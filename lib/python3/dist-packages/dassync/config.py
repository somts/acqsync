'''Data Acquistion System Sync (DASSync) lib file
Parse args and conf file and set up logging.
'''
# CHANGELOG:
# 2021-06 jmeyer: Initial creation. Splay off config to its own class.
#                 It was getting unweildy to manage to add features.

import argparse
import datetime
import logging
import logging.handlers
import re
import sys
from itertools import chain
from multiprocessing import cpu_count
from pathlib import Path
from types import SimpleNamespace

from jinja2 import Template
import yaml
from .error import ConfigFileSyntaxError, FatalError


class DSConfig:
    ''''Setting up process configuration:',
        '1. Read YAML config and CLI args',
        '2. Set self variables
         3. Create a list of jobs that will be used by DASSync'''

    # We need to validate rsync options.  This list was taken
    # from rsync version 3.1.3 protocol version 31. The CLI to get this
    # into a Python list syntax from the rsync client was:
    # rsync --help 2>&1 | \
    #  awk '{ if ( $1 ~ "--" || $2 ~ "--") {
    #           if ( $1 ~ /^--/ ) {print $1}
    #           else {print $2}}}' | \
    #  sed -e 's/^--//' -e 's/=.\+$//' -e "s/^/    '/" -e "s/$/',/" | \
    #  sort
    RSYNC_OPTIONS_VALID = [
      '8-bit-output', 'acls', 'address', 'append', 'append-verify',
      'archive', 'backup', 'backup-dir', 'block-size', 'blocking-io',
      'bwlimit', 'checksum', 'checksum-choice', 'checksum-seed',
      'chmod', 'chown', 'compare-dest', 'compress', 'compress-level',
      'contimeout', 'copy-dest', 'copy-dirlinks', 'copy-links',
      'copy-unsafe-links', 'cvs-exclude', 'debug', 'del',
      'delay-updates', 'delete', 'delete-after', 'delete-before',
      'delete-delay', 'delete-during', 'delete-excluded',
      'delete-missing-args', 'devices', 'dirs', 'dry-run', 'exclude',
      'exclude-from', 'executability', 'existing', 'fake-super',
      'files-from', 'filter', 'force', 'from0', 'fuzzy', 'group',
      'groupmap', 'hard-links', 'help', 'human-readable', 'iconv',
      'ignore-errors', 'ignore-existing', 'ignore-missing-args',
      'ignore-times', 'include', 'include-from', 'info', 'inplace',
      'ipv4', 'ipv6', 'itemize-changes', 'keep-dirlinks', 'link-dest',
      'links', 'list-only', 'log-file', 'log-file-format',
      'max-delete', 'max-size', 'min-size', 'modify-window',
      'msgs2stderr', 'munge-links', 'no-implied-dirs', 'no-motd',
      'noatime', 'numeric-ids', 'omit-dir-times', 'omit-link-times',
      'one-file-system', 'only-write-batch', 'out-format', 'outbuf',
      'owner', 'partial', 'partial-dir', 'password-file', 'perms',
      'port', 'preallocate', 'progress', 'protect-args', 'protocol',
      'prune-empty-dirs', 'quiet', 'read-batch', 'recursive',
      'relative', 'remote-option', 'remove-source-files', 'rsh',
      'rsync-path', 'safe-links', 'size-only', 'skip-compress',
      'sockopts', 'sparse', 'specials', 'stats', 'stop-at', 'suffix',
      'super', 'temp-dir', 'time-limit', 'timeout', 'times', 'update',
      'usermap', 'verbose', 'version', 'whole-file', 'write-batch',
      'xattrs']

    # Append 'no-' options to above and convert to a sorted tuple.
    # Almost all long strings in rsync can be prepended with 'no-' to
    # negate implicit commands. To account for this, we'll simply
    # duplicate the above list, prepending 'no-' to each item. This
    # causes a handful of non-sensical options like --no-version to be
    # pass validation in Python.  However, since rsync will generate
    # an error at runtime for those few not-really-valid "no-" options,
    # we tolerate the cheap hack, here, as a list that has a few too
    # many options is better than no validation in Python whatsoever.
    # NOTE: our final product is a tuple as we no longer want to modify
    # afterwards, plus this enables more efficient validity checking.
    RSYNC_OPTIONS_VALID = tuple(sorted(
        RSYNC_OPTIONS_VALID + ['no-{0}'.format(i) for i in
                               RSYNC_OPTIONS_VALID]))

    def __init__(self,
                 cmdpath='/usr/bin/rsync',
                 rsyncopts={'archive': True,
                            'chmod': 'Dg+st,ugo+rx,Fo-w,+X',
                            'exclude': ['Trash*/"', '_*"', 'DS_Store',
                                        'TemporaryItems/', 'Thumbs.db'],
                            'no-g': True,
                            'no-p': True,
                            'one-file-system': True,
                            'timeout': '60'}):
        # setup/defaults
        self.paths = SimpleNamespace()

        # Continue setup, potentially based on user input
        self.__conf_args()

        # Allow YAML to override/augment user options
        self.yaml = self.__open_yaml()
        self.check_yaml_conf()
        self.jobs = []  # we need a blank list for YAML items

        self.check_yaml_items()

        # Set up logger, post CLI/YAML eval
        self.logconf = SimpleNamespace(consolehandler=logging.StreamHandler())
        self.logger = logging.getLogger('DASSync')

        # Set up rfhandler, based on derived logfile
        setattr(
            self.logconf,
            'rfhandler',
            logging.handlers.RotatingFileHandler(
                self.paths.logfile,
                maxBytes=1024*1024,
                backupCount=4
            )
        )

        # With setup complete, configure our logger
        self.__conf_log()

        # Sort rendered commands. In multithreading, they get executed
        # in somewhat arbitrary order, but this makes debugging easier.
        self.jobs.sort()

    def __conf_log(self):
        '''Configure logging object for use from acqsync'''

        # pass all messages down to handlers
        self.logger.setLevel(logging.DEBUG)

        # custom log formatter
        # '[%(levelname)s] %(asctime)s %(lineno)d %(message)s'
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)7s %(funcName)12s ' +
            '%(threadName)10s: %(message)s')

        # RotatingFileHandler logger
        self.logconf.rfhandler.setFormatter(formatter)
        self.logconf.rfhandler.setLevel(logging.INFO)
        self.logger.addHandler(self.logconf.rfhandler)

        # syslog logger -- commented out because it requires
        # editing /etc/syslog.conf
        #
        # syslogHandler = logging.handlers.SysLogHandler()
        # syslogHandler.setFormatter(formatter)
        # syslogHandler.setLevel(logging.ERROR)
        # self.logger.addHandler(syslogHandler)

        # console logger
        self.logconf.consolehandler.setLevel(logging.INFO)
        self.logconf.consolehandler.setFormatter(formatter)
        self.logger.addHandler(self.logconf.consolehandler)

        # Tweak logger settings based on userland args
        if self.dry_run or self.debug:
            # Enable this script and rsync to be more chatty
            self.logconf.rfhandler.setLevel(logging.DEBUG)
            self.logconf.consolehandler.setLevel(logging.DEBUG)

        # Disable most STDOUT and avoid general cron noise if in quiet mode
        if self.quiet:
            self.logconf.consolehandler.setLevel(logging.FATAL)

    def __conf_args(self):
        '''parse STDIN, if any'''

        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            description='''
                Build and execute a series of CLI rsync commands
                in order to synchronize data from our
                Data Acquisition Systems (DAS) to a central server.'''
        )

        parser.add_argument(
            '-L', '--logfile',
            dest='logfile',
            default=Path.joinpath(Path(__file__).parents[4].absolute(),
                                  'var', 'log', 'acqsync.log'),
            type=lambda p: Path(p).absolute(),
            help='log file to write to')
        parser.add_argument(
            '-P', '--pidfile',
            dest='pidfile',
            default=Path.joinpath(Path(__file__).parents[4].absolute(),
                                  'var', 'run', 'acqsync.pid'),
            type=lambda p: Path(p).absolute(),
            help='PID file to track')
        parser.add_argument(
            '-Y', '--yamlfile',
            dest='yamlfile',
            default=Path.joinpath(Path(__file__).parents[4].absolute(),
                                  'etc', 'acqsync.yaml'),
            type=lambda p: Path(p).absolute(),
            help='YAML file to read configuration from')
        parser.add_argument(
            '-t', '--threadcount',
            dest='threadcount',
            default=cpu_count()*4,
            type=int,
            help='number of parallel rsync jobs to run')
        parser.add_argument(
            '-W', '--critical-time',
            default=0,
            dest='critical_time',
            type=int,
            help='Generate an error if all syncs take longer than a ' +
                 'certain amount of seconds (EG 900), which can create ' +
                 'email in some cron setups. Set to 0 to disable.')
        parser.add_argument(
            '-R', '--critical-subprocess',
            action='store_true',
            dest='critical_subprocess',
            help='Generate an error if any rsync subprocess returns ' +
                 'non-zero value, which can generate email in some ' +
                 'cron setups')

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

        args = parser.parse_args()

        # Update self intially with args. Values set here may
        # subsequently be overridden by YAML, however what is set
        # here controls what YAML file we open.
        for key, val in args.__dict__.items():
            if key.endswith('file'):
                setattr(self.paths, key, val)
            else:
                setattr(self, key, val)

    def __open_yaml(self):
        '''Attempt to open our YAML file'''
        try:
            with open(self.paths.yamlfile, 'rb') as cfg:
                myyaml = yaml.load(cfg, Loader=yaml.FullLoader)
        except IOError as err:
            raise FatalError(
                'Cannot locate or open %s.' % self.paths.yamlfile, err)
        except ValueError as err:
            raise ConfigFileSyntaxError(
                'Syntax error in targets file %s.' % self.paths.yamlfile,
                err)
        return myyaml

    def check_yaml_conf(self):
        '''Validate configuration root key from YAML'''

        # YAML may override our default rsync path
        if 'path' in self.yaml['configuration']['rsync']:
            self.cmdpath = self.yaml['configuration']['rsync']['path']

        # YAML may override our default rsync options
        if 'options' in self.yaml['configuration']['rsync']:
            self.rsyncopts = self.parse_rsyncopts(
                    self.yaml['configuration']['rsync']['options'])

        # Convert YAML to SimpleNamespaces. Process required keys
        for i in ['configuration', 'items']:
            try:
                if i == 'configuration':  # Process subkeys in config
                    for j in ['cruise', 'paths', 'rsync']:
                        if j == 'cruise':
                            setattr(self, j,
                                    self.parse_cruise(self.yaml[i][j]))
                        elif j == 'paths':
                            for k, v in self.yaml[i][j].items():
                                setattr(self, '%sfile' % k, v)
                        else:
                            setattr(self, j,
                                    SimpleNamespace(**self.yaml[i][j]))
                else:
                    # root key "items" (and future)
                    setattr(self, i, SimpleNamespace(**self.yaml[i]))
            except AttributeError as err:
                raise ConfigFileSyntaxError(
                    'root key "%s" is not defined in %s! Exit.' %
                    (i, self.paths.yamlfile), err)

    def check_yaml_items(self):
        '''Confirm all YAML items received are valid and append fully
           rendered CLI command to list of jobs.'''

        for key, val in self.yaml['items'].items():
            value = SimpleNamespace(**val)

            try:
                if value.enabled is False:  # ignore disabled
                    continue
            except AttributeError:  # implicit enabled
                pass

            # set module-specific rsync options
            try:
                if not isinstance(value.rsync_options, dict):
                    raise ConfigFileSyntaxError(
                        'rsync_options in module "%s" (%s) ' %
                        (key, self.paths.yamlfile) +
                        'must be type dict, got %s' %
                        type(value.rsync_options))
            except AttributeError:
                value.rsync_options = {}

            # Run each module through Jinja2 templating engine
            try:
                srctemplate = Template(value.src)
            except AttributeError:  # key when value.src is not present
                srctemplate = Template(key)
            finally:
                dsttemplate = Template(value.dst)
                value.src = srctemplate.render(
                    cruise=self.cruise,
                    paths=self.paths,
                    rsync=self.rsync)
                value.dst = dsttemplate.render(
                    cruise=self.cruise,
                    paths=self.paths,
                    rsync=self.rsync)

            # Determine if we need to execute in a subshell. This is
            # less efficient, but required for globbing, which is
            # often used. As such, it is true by default, for now
            try:
                shellbool = value.shell
            except AttributeError:
                shellbool = True

            # TODO: move me?
            # Attempt to make parent dir if it does not exist
            # if not os.path.isdir(os.path.dirname(value.dst)):
            #    self.logger.debug('Creating "%s"', value.dst)
            #    os.makedirs(value.dst)

            # Update self
            setattr(self.items, key, value)

            # build cmd using list() + chain() in order to
            # create a flattened list. We then join on space specifically
            # because shell=True in subprocess (which requires this).
            # NOTE: we make our rsync options a set() in order to reduce
            #       non-sensical double calls EG --verbose --verbose
            self.jobs.append(
                (list(chain([self.rsync.path],
                            sorted(set(
                                self.parse_rsyncopts(self.rsync.options) +
                                self.parse_rsyncopts(value.rsync_options))),
                            [value.src, value.dst])),
                 shellbool))

    @staticmethod
    def parse_cruise(cdict,
                     params=['begin', 'end', 'id', 'sync_run'],
                     pattern='^[A-Z]{2,3}([0-9]{4}|port)$'):
        '''confirm cruise metadata settings follow a certain schema'''
        keys = sorted(cdict.keys())

        # Confirm that we received only the cruise parameters we expect.
        if keys != params:
            raise ConfigFileSyntaxError(
                'Supported Cruise parameters are %s. Got %s' %
                (params, keys))
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
                elif i == 'id':
                    # Ensure our cruise id matches a defined pattern
                    # EG RRport, HLY1234, SP4321
                    match = re.search(pattern, cdict[i])
                    if not match:
                        raise ConfigFileSyntaxError(
                            'Cruise id "%s" must match pattern "%s". Exit.' %
                            (cdict[i], pattern))
                elif i == 'sync_run':
                    # Ensure sync_run is defined and a bool
                    if not isinstance(cdict[i], bool):
                        raise ConfigFileSyntaxError(
                            'Cruise sync_run must be defined and a boolean')
            except KeyError:
                raise ConfigFileSyntaxError(
                    'Required cruise parameter "%s" is not defined. Exit.' % i)

        return SimpleNamespace(**cdict)

    def parse_rsyncopts(self, opts_dict):
        '''Convert a dict of rsync options to an array of rsync CLI
           options, verifying them against cached valid options from
           `man rsync`.'''
        opts_list = []

        # Override rsync verbosity, based on CLI args
        if self.dry_run or self.debug:
            opts_dict['quiet'] = False
            opts_dict['verbose'] = True

            if self.dry_run:
                # Override rsync copying behavior
                opts_dict['dry-run'] = True
        else:
            # Override rsync verbosity: only print errors to console
            opts_dict['quiet'] = True
            opts_dict['verbose'] = False

        for key, val in opts_dict.items():
            if key not in self.RSYNC_OPTIONS_VALID:
                raise ConfigFileSyntaxError(
                    'Unsupported rsync option "%s".\n' % key +
                    'Valid options are %s' %
                    ', '.join(self.RSYNC_OPTIONS_VALID))

            if isinstance(val, bool):
                if val is True:
                    opts_list.append('--%s' % key)
            elif isinstance(val, list):
                for i in val:
                    opts_list.append('--%s="%s"' % (key, i))
            else:
                opts_list.append('--%s="%s"' % (key, val))

        return opts_list

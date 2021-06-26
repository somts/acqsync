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
from itertools import chain
from multiprocessing import cpu_count
from pathlib import Path, PosixPath, WindowsPath

from jinja2 import Template
import yaml
from .error import DSConfigSyntaxError, DSError
from .rsync import DSRsync


class DSConfig:
    ''''Setting up process configuration:',
        '1. Read YAML config and CLI args',
        '2. Set self variables
         3. Create a list of jobs that will be used by DASSync'''

    def __init__(self,
                 cmdpath='/usr/bin/rsync',
                 rsyncopts={'archive': True,
                            'chmod': 'Dg+st,ugo+rx,Fo-w,+X',
                            'exclude': ['Trash*/', '_*', 'DS_Store',
                                        'TemporaryItems/', 'Thumbs.db'],
                            'no-g': True,
                            'no-p': True,
                            'timeout': 60,
                            'contimeout': 10}):
        # setup/defaults
        self.dsrsync = DSRsync()  # instance to interact with rsync
        self.paths = argparse.Namespace()
        self.makedirs = set()

        self.paths.etc = Path.joinpath(
            Path(__file__).parents[4].absolute(), 'etc')

        # Continue setup, potentially based on user input
        # Update self intially with user args. Values set here may
        # subsequently be overridden by YAML, however what is set
        # here controls what YAML file we open.
        for key, val in self.__conf_args().__dict__.items():
            if key.endswith('path'):
                # Map anything that ends with 'path' to self.conf.paths
                # removing the 'path' portion of the variable name.
                # This allows us to keep the naming in YAML cleaner
                # (EG paths.pid)
                setattr(self.paths, key.replace('path', ''), val)
            else:
                setattr(self, key, val)

        # Allow YAML to override/augment user options
        self.yaml = self.__open_yaml()
        self.check_yaml_conf()
        self.enabled_jobs = []  # we need a blank list for YAML items
        self.disabled_jobs = []  # we need a blank list for YAML items
        self.cruise.days = (self.cruise.end - self.cruise.begin).days
        self.check_yaml_items()

        # Normalize self.paths variables to Path types after allowing
        # our templating engine to expand cruise variables.
        namespace = {'cruise': self.cruise}
        for key, val in self.paths.__dict__.items():
            if isinstance(val, Path):
                val = val.__str__()
            setattr(self.paths, key, Path(self.templatize(val, namespace)))

        # Set up logger, post CLI/YAML eval
        self.logconf = argparse.Namespace(
            consolehandler=logging.StreamHandler())
        self.logger = logging.getLogger('DASSync')

        # Set up rfhandler, based on derived logfile
        # As this tool is for near real-time data transfer, there is
        # not really a need to troubleshoot very far back in time, so,
        # hard-code the log file size and backup count to values that
        # will not overwhelm small filesystems. Python itself rotates
        # the log(s) when needed, allowing us to store the log outside
        # of a logrotate dependency.
        try:
            setattr(self.logconf, 'rfhandler',
                    logging.handlers.RotatingFileHandler(
                        self.paths.log.__str__(), maxBytes=26214400,
                        backupCount=3))
        except FileNotFoundError:
            raise DSError('Not able to open log file %s!' % self.paths.log)

        # With setup complete, configure our logger
        self.__conf_log()

        self.logger.info('Rsync version is %s', self.dsrsync.version)
        self.logger.info('Rsync protocol version is %d', self.dsrsync.protocol)
        self.logger.info('Configured cruise, %s, is %d days long (%s to %s)',
                         self.cruise.id, self.cruise.days,
                         self.cruise.begin, self.cruise.end)

        # Sort rendered commands. Multithreading may execute in
        # arbitrary order, so this is really just to make testing with
        # the -b option more readable.
        self.enabled_jobs.sort()
        self.disabled_jobs.sort()

    @staticmethod
    def __conf_args():
        '''parse STDIN, if any'''

        parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            description='''
                Build and execute a series of CLI rsync commands
                in order to synchronize data from our
                Data Acquisition Systems (DAS) to a central server.'''
        )

        parser.add_argument(
            '-L', '--logpath',
            dest='logpath',
            default=Path.joinpath(Path(__file__).parents[4].absolute(),
                                  'var', 'log', 'acqsync.log'),
            type=lambda p: Path(p).absolute(),
            help='log file to write to')
        parser.add_argument(
            '-P', '--pidpath',
            dest='pidpath',
            default=Path.joinpath(Path(__file__).parents[4].absolute(),
                                  'var', 'run', 'acqsync.pid'),
            type=lambda p: Path(p).absolute(),
            help='PID file to track')
        parser.add_argument(
            '-Y', '--yamlpath',
            dest='yamlpath',
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
        parser.add_argument(
            '-S', '--shell',
            action='store_true',
            dest='shell',
            help='Set default subprocess shell value. Disabling ' +
            'shells can be more efficient and allow better ' +
            'cross-platform support, but globbing is not possible. ' +
            'Note that some strings will automatically enable shell')
        parser.add_argument(
            '-n', '--dry-run',
            action='store_true',
            dest='dry_run',
            help='Set rsync subprocess(s) to --dry-run mode.')

        agroup = parser.add_mutually_exclusive_group()
        agroup.add_argument(
            '-b', '--build-only',
            action='store_true',
            dest='build_only',
            help='Build rsync commands and log; do not `rsync --dry-run`')
        agroup.add_argument(
            '-d', '--debug',
            action='store_true',
            dest='debug',
            help='Turn on debugging output.')
        agroup.add_argument(
            '-q', '--quiet',
            action='store_true',
            dest='quiet',
            help='Minor(-W/-R) or no logging to STDOUT (EG for cron).')
        agroup.add_argument(
            '-v', '--verbose',
            action='store_true',
            dest='verbose',
            help='Turn on verbose output.')

        return parser.parse_args()

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

    def __open_yaml(self):
        '''Attempt to open our YAML file'''
        try:
            with open(self.paths.yaml, 'rb') as cfg:
                myyaml = yaml.load(cfg, Loader=yaml.FullLoader)
        except IOError as err:
            raise DSError(
                'Cannot locate or open %s.' % self.paths.yaml, err)
        except ValueError as err:
            raise DSConfigSyntaxError(
                'Syntax error in targets file %s.' % self.paths.yaml,
                err)
        return myyaml

    def check_yaml_conf(self):
        '''Validate configuration root key from YAML'''

        # Convert YAML to argparse.Namespace. Process required keys
        for i in ['configuration', 'items']:
            if i not in self.yaml:
                raise DSConfigSyntaxError(
                    'root key "%s" is not defined in %s!' %
                    (i, self.paths.yaml))
            if i == 'configuration':  # Process subkeys in config
                try:
                    setattr(self, 'cruise', self.parse_cruise(
                        self.yaml[i]['cruise']))
                    setattr(self, 'rsync', argparse.Namespace(
                        **self.yaml[i]['rsync']))
                    for key, val in self.yaml[i]['paths'].items():
                        setattr(self.paths, key, val)
                except (KeyError, AttributeError) as err:
                    raise DSConfigSyntaxError(
                        'unexpected attribute or key: %s' % err)
            else:
                # root key "items" (and future)
                setattr(self, i, argparse.Namespace(**self.yaml[i]))

        # Normalize/validate rsync path
        try:
            if not isinstance(self.rsync.path, PosixPath) and \
                    not isinstance(self.rsync.path, WindowsPath):
                self.rsync.path = Path(self.rsync.path)
        except AttributeError:
            self.rsync.path = Path(self.cmdpath)  # use class default
        finally:
            # Convert to string
            self.rsync.path = str(self.rsync.path)

        # Normalize rsync options
        try:
            if not isinstance(self.rsync.options, dict):
                raise DSConfigSyntaxError('self.rsync.options not a dict()!')
        except AttributeError:
            self.rsync.options = self.rsyncopts

    def check_yaml_items(self):
        '''Confirm all YAML items received are valid and append fully
           rendered CLI command to list of jobs.'''

        for key, value in self.yaml['items'].items():
            item = self._item_validate(key, value)

            try:
                # Special behavior needed when filter_date is set
                # We expect a str and it should convert to a Path.
                if isinstance(item.filter_date, str):
                    item.filter_date = Path(item.filter_date)
                else:
                    raise DSConfigSyntaxError(
                        'filter_date must be a string')
            except AttributeError:
                pass
            else:
                # Convert filter_date to a list of filter args

                filters = set()  # STEP 1: prepare an empty set

                for date in [self.cruise.begin + datetime.timedelta(days=x)
                             for x in range(0, self.cruise.days + 1)]:
                    mypath = date.strftime(item.filter_date.__str__())

                    # STEP 2: add parent paths to --filter

                    # NOTE: Calculate parent path(s) for every rendered
                    # path. This catchs year-based and month-based
                    # parent directories. The Python set() type avoids
                    # duplicating such parents, so we can afford to be
                    # messy since cruises tend to be, at most 60 days,
                    # and so (re)calculating is cheap enough...

                    # The last parent is either '.' or '/'. Excise.
                    parents = list(Path(mypath).parents)[:-1]
                    parents.reverse()  # Lowest level dir first
                    for i in parents:
                        filters.add('+ %s/' % i)

                    # STEP 3: add specific filenames based on date
                    #         range. This all gets sorted().
                    filters.add('+ %s' % mypath)

                filters.add('- *')  # STEP 4: exclude anything else

                # STEP 5: sort and convert to expected data type
                filters = sorted(filters)

                # STEP 6: append to or create --filter
                try:
                    item.options['filter'] += filters
                except KeyError:
                    item.options['filter'] = filters

                # STEP 7: sanitize item before build
                del item.filter_date
            finally:
                self._item_build_job(key, item)  # Build singleton job

    @staticmethod
    def templatize(mystr, namespaces={}):
        '''Apply Jinja2 expansion to a string and return.'''
        template = Template(mystr)
        return template.render(**namespaces)

    def _item_build_job(self, name, item):
        '''Build an rsync job from a argparse.Namespace object and a name.
           Append to self.*jobs when done.'''

        namespace = {'cruise': self.cruise, 'paths': self.paths,
                     'rsync': self.rsync}

        # Register a need to make parent dir(s) when they do not exist
        # after running rname through Jinja2 templating engine. This
        # should only apply to enabled items.
        pdir = Path(self.templatize(item.dst, namespace)).parent
        if not pdir.is_dir() and item.enable:
            self.makedirs.add(pdir)

        # Merge main and specific dicts(); override shell as needed
        opts, item.shell = self.dsrsync.parse_rsyncopts(
            {**self.rsync.options, **item.options},
            self.dry_run, self.debug, self.quiet, self.verbose, item.shell)

        # Build job using list() + chain() to create a flattened list.
        job = list(chain([self.rsync.path], opts, [item.src, item.dst]))

        # Run job list through Jinja2 templating engine
        job = [self.templatize(x, namespace) for x in job]

        # Job is tuple(cmd, shell) to pass to Pool.starmap()
        # Whether enabled or not, we want to render/test/log
        # all items in our configuration
        if item.enable is True:
            self.enabled_jobs.append((job, item.shell))
        else:
            self.disabled_jobs.append((job, item.shell))

    def _item_validate(self, key, value):
        '''Take a YAML hash and convert to argparse.Namespace,
           validating the values received and setting defaults for
           required paramters.'''
        # Define supported values and default values (not None) when
        # defaults are desired
        supported_types = {'dst': str, 'enable': bool,
                           'filter_date': str, 'options': dict,
                           'shell': bool, 'src': str}
        supported_keys = supported_types.keys()
        supported_defaults = {'enable': True, 'options': {},
                              'shell': self.shell, 'src': key}

        item = argparse.Namespace(**value)

        # Set defaults when values are absent.
        for reqkey, defval in supported_defaults.items():
            if not item.__contains__(reqkey):
                setattr(item, reqkey, defval)

        # Confirm valid data types
        for i in item.__dict__.keys():
            if i not in supported_keys:
                raise DSConfigSyntaxError(
                    '"%s" is not a supported item parameter.' % i)

            if not isinstance(getattr(item, i), supported_types[i]):
                raise DSConfigSyntaxError(
                    'Expected %s data type for items.%s.%s.' % (
                        supported_types[i], key, i))

            if i in ('src', 'dst'):
                setattr(item, i, str(getattr(item, i)))  # ensure str

        # Special Case: prepend relative item
        try:
            if self.paths.dstbase and not Path(item.dst).is_absolute():
                item.dst = Path(
                    self.paths.dstbase).joinpath(item.dst).__str__()
        except AttributeError as err:
            print(err)
        return item

    @staticmethod
    def parse_cruise(cdict,
                     params=('begin', 'end', 'id', 'operator', 'ports',
                             'sync_run', 'vessel'),
                     pattern='^[A-Z]{2,3}([0-9]{4}|port)$'):
        '''confirm cruise metadata settings follow a certain schema'''
        keys = tuple(sorted(cdict.keys()))

        # Confirm that we received only the cruise parameters we expect
        if keys != params:
            raise DSConfigSyntaxError(
                'Supported Cruise parameters are %s. Got %s' %
                (params, keys))

        for i in params:
            try:
                if i in ('begin', 'end'):
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
                        raise DSConfigSyntaxError(
                            'Cruise id "%s" must match pattern "%s". Exit.' %
                            (cdict[i], pattern))
                elif i == 'sync_run':
                    # Ensure sync_run is defined and a bool
                    if not isinstance(cdict[i], bool):
                        raise DSConfigSyntaxError(
                            'Cruise sync_run must be defined and a boolean')
            except KeyError:
                raise DSConfigSyntaxError(
                    'Required cruise parameter "%s" is not defined. Exit.' % i)

        return argparse.Namespace(**cdict)

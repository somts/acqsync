'''DASSync module to generate errors and exceptions'''


class DSError(Exception):
    '''Hack our own fatal error class'''
    def __init__(self, errmsg, exception=None):
        super().__init__()
        self.errmsg = errmsg
        self.exception = exception

    def __str__(self):
        if self.exception is not None:
            return '\n\t'.join((self.errmsg, '%s' % self.exception))
        return self.errmsg


class DSRsyncError(DSError):
    '''Hack our own fatal error class'''


class DSConfigSyntaxError(DSError):
    '''Hack our own fatal error class'''


class DSConfigTargetError(DSError):
    '''Hack our own fatal error class'''

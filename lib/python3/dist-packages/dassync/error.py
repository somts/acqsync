#!/usr/bin/env python3


class FatalError(Exception):
    '''Hack our own fatal error class'''
    def __init__(self, errmsg, exception=None):
        super().__init__()
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

"""
Python bindings to odesk API
python-odesk version 0.4
(C) 2010-2011 oDesk
"""

import logging
import urllib2


class BaseException(Exception):
    def __init__(self, *args, **kwargs):
        logging.debug("[python-odesk]:" + unicode(s) for s in args)
        super(BaseException, self).__init__()


class HTTP400BadRequestError(urllib2.HTTPError, BaseException):
    pass


class HTTP401UnauthorizedError(urllib2.HTTPError, BaseException):
    pass


class HTTP403ForbiddenError(urllib2.HTTPError, BaseException):
    pass


class HTTP404NotFoundError(urllib2.HTTPError, BaseException):
    pass


class InvalidConfiguredException(BaseException):
    pass


class APINotImplementedException(BaseException):
    pass


class AuthenticationError(BaseException):
    pass


class NotAuthenticatedError(BaseException):
    pass

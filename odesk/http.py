"""
Python bindings to odesk API
python-odesk version 0.4
(C) 2010-2011 oDesk
"""

import cookielib
from datetime import date
import hashlib
import logging
import urllib
import urllib2


try:
    import json
except ImportError:
    import simplejson as json

from odesk.exceptions import *
from odesk.utils import *


def raise_http_error(e):
    '''Raise custom exception'''
    if e.code == 400:
        raise HTTP400BadRequestError(e.filename, e.code, e.msg,
                                     e.hdrs, None)
    elif e.code == 401:
        raise HTTP401UnauthorizedError(e.filename, e.code, e.msg,
                                       e.hdrs, None)
    elif e.code == 403:
        raise HTTP403ForbiddenError(e.filename, e.code, e.msg,
                                    e.hdrs, None)
    elif e.code == 404:
        raise HTTP404NotFoundError(e.filename, e.code, e.msg,
                                   e.hdrs, None)
    else:
        raise e


class HttpRequest(urllib2.Request):
    """
    A hack around Request class that allows to specify HTTP method explicitly
    """

    def __init__(self, *args, **kwargs):
        #Request is an old-style class, so can't use `super`
        method = kwargs.pop('method', 'GET')
        urllib2.Request.__init__(self, *args, **kwargs)
        self.method = method

    def get_method(self):
        #FIXME: Http method hack. Should be removed once oDesk supports true
        #HTTP methods
        if self.method in ['PUT', 'DELETE']:
            return 'POST'
        #End of hack

        return self.method

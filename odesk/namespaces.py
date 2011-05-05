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


from odesk.http import *
from odesk.utils import *


class Namespace(object):
    """
    A special 'proxy' class to keep API methods organized
    """

    base_url = 'https://www.odesk.com/api/'
    api_url = None
    version = 1

    def __init__(self, client):
        self.client = client

    def full_url(self, url):
        """
        Gets relative URL of API method and returns a full URL
        """
        return "%s%sv%d/%s" % (self.base_url, self.api_url, self.version, url)

    #Proxied client's methods
    def get(self, url, data={}):
        return self.client.get(self.full_url(url), data)

    def post(self, url, data={}):
        return self.client.post(self.full_url(url), data)

    def put(self, url, data={}):
        return self.client.put(self.full_url(url), data)

    def delete(self, url, data={}):
        return self.client.delete(self.full_url(url), data)


class GdsNamespace(Namespace):
    base_url = 'https://www.odesk.com/gds/'

    def urlopen(self, url, data={}, method='GET'):
        data = data.copy()
        query = self.client.urlencode(data)
        if method == 'GET':
            url += '?' + query
            request = HttpRequest(url=url, data=None, method=method)
            return urllib2.urlopen(request)
        return None

    def read(self, url, data={}, method='GET'):
        """
        Returns parsed Python object or raises an error
        """
        try:
            response = self.urlopen(url, data, method)
        except urllib2.HTTPError, e:
            raise_http_error(e)

        result = json.loads(response.read())
        return result

    def get(self, url, data={}):
        return self.read(self.full_url(url), data, method='GET')


class NonauthGdsNamespace(GdsNamespace):
    '''
    This class does not add authentication parameters
    to request urls (api_sig, api_key & api_token)
    Some APIs return error if called with authentication parameters
    '''
    def urlopen(self, url, data={}, method='GET'):
        if method == 'GET':
            request = HttpRequest(url=url, data=data.copy(),
                    method=method)
            return urllib2.urlopen(request)
        return None

"""
Python bindings to odesk API
python-odesk version 0.4
(C) 2010-2011 oDesk
"""
VERSION = (0, 4, 0, 'final', 5)


def get_version():
    version = '%s.%s' % (VERSION[0], VERSION[1])
    if VERSION[2]:
        version = '%s.%s' % (version, VERSION[2])
    if VERSION[3:] == ('alpha', 0):
        version = '%s pre-alpha' % version
    else:
        if VERSION[3] != 'final':
            version = "%s %s" % (version, VERSION[3])
            if VERSION[4] != 0:
                version = '%s %s' % (version, VERSION[4])
    return version


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


from odesk.auth import *
from odesk.exceptions import *
from odesk.http import *
from odesk.namespaces import *
from odesk.oauth import OAuth
from odesk.utils import *


__all__ = ["get_version", "Client", "utils"]


def _utf8_str(obj):
    try:
        return unicode(obj).encode("utf8")
    except UnicodeDecodeError, e:
        # input could be an utf8 encoded
        obj.decode("utf8")  # check if it is a valid utf8 string
        return obj


def signed_urlencode(secret, query={}):
    """
    Converts a mapping object to signed url query

    >>> signed_urlencode('some$ecret', {})
    'api_sig=5da1f8922171fbeffff953b773bcdc7f'
    >>> signed_urlencode('some$ecret', {'spam':42,'foo':'bar'})
    'api_sig=11b1fc2e6555297bdc144aed0a5e641c&foo=bar&spam=42'
    """
    message = secret
    for key in sorted(query.keys()):
        try:
            message += _utf8_str(key) + _utf8_str(query[_utf8_str(key)])
        except Exception, e:
            logging.debug("[python-odesk] Error while trying to sign key: %s and query %s" % (key, query[key]))
            raise e
    #query = query.copy()
    _query = {}
    _query['api_sig'] = hashlib.md5(message).hexdigest()
    for k, v in query.iteritems():
        _query[_utf8_str(k)] = _utf8_str(v)
    return urllib.urlencode(_query)


class BaseClient(object):
    """
    A basic HTTP client which supports signing of requests as well
    as de-serializing of responses.
    """

    def __init__(self, public_key, secret_key, api_token=None):
        self.public_key = public_key
        self.secret_key = secret_key
        self.api_token = api_token
        self.auth = None

    def urlencode(self, data={}):
        data = data.copy()
        data['api_key'] = self.public_key
        if self.api_token:
            data['api_token'] = self.api_token
        return signed_urlencode(self.secret_key, data)

    def urlopen(self, url, data={}, method='GET'):
        data = data.copy()

        #FIXME: Http method hack. Should be removed once oDesk supports true
        #HTTP methods
        if method in ['PUT', 'DELETE']:
            data['http_method'] = method.lower()
        #End of hack

        self.last_method = method
        self.last_url = url
        self.last_data = data

        if isinstance(self.auth, OAuth):
            query = self.auth.urlencode(url, self.oauth_access_token,\
                self.oauth_access_token_secret, data)
        else:
            query = self.urlencode(data)

        if method == 'GET':
            url += '?' + query
            request = HttpRequest(url=url, data=None, method=method)
        else:
            request = HttpRequest(url=url, data=query, method=method)
        return urllib2.urlopen(request)

    def read(self, url, data={}, method='GET', format='json'):
        """
        Returns parsed Python object or raises an error
        """
        assert format == 'json', "Only JSON format is supported at the moment"
        url += '.' + format
        try:
            response = self.urlopen(url, data, method)
        except urllib2.HTTPError, e:
            raise_http_error(e)

        if format == 'json':
            result = json.loads(response.read())
        return result


class Client(BaseClient):
    """
    Main API client
    """

    def __init__(self, public_key, secret_key, api_token=None,
                oauth_access_token=None, oauth_access_token_secret=None,
                format='json', auth='simple', finance=True, finreport=True,
                hr=True, mc=True, oconomy=True, provider=True,
                task=True, team=True, ticket=True, timereport=True, url=True):

        self.public_key = public_key
        self.secret_key = secret_key
        self.api_token = api_token
        self.format = format

        if auth == 'simple':
            self.auth = Auth(self)
        elif auth == 'oauth':
            self.auth = OAuth(self)
            self.oauth_access_token = oauth_access_token
            self.oauth_access_token_secret = oauth_access_token_secret

        #Namespaces
        if finance:
            from odesk.routers.finance import Finance
            self.finance = Finance(self)

        if finreport:
            from odesk.routers.finreport import Finreports
            self.finreport = Finreports(self)

        if hr:
            from odesk.routers.hr import HR
            self.hr = HR(self)

        if mc:
            from odesk.routers.mc import *
            self.mc = MC(self)

        if oconomy:
            from odesk.routers.oconomy import OConomy, NonauthOConomy
            self.oconomy = OConomy(self)
            self.nonauth_oconomy = NonauthOConomy(self)

        if provider:
            from odesk.routers.provider import Provider
            self.provider = Provider(self)

        if task:
            from odesk.routers.task import Task
            self.task = Task(self)

        if team:
            from odesk.routers.team import Team
            self.team = Team(self)

        if ticket:
            from odesk.routers.ticket import Ticket
            self.ticket = Ticket(self)

        if timereport:
            from odesk.routers.timereport import TimeReport
            self.timereport = TimeReport(self)

        if url:
            from odesk.routers.url import Url
            self.url = Url(self)

    #Shortcuts for HTTP methods
    def get(self, url, data={}):
        return self.read(url, data, method='GET', format=self.format)

    def post(self, url, data={}):
        return self.read(url, data, method='POST', format=self.format)

    def put(self, url, data={}):
        return self.read(url, data, method='PUT', format=self.format)

    def delete(self, url, data={}):
        return self.read(url, data, method='DELETE', format=self.format)


if __name__ == "__main__":
    import doctest
    doctest.testmod()

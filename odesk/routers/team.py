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


from odesk.namespaces import Namespace


class Team(Namespace):

    api_url = 'team/'
    version = 1

    def get_teamrooms(self):
        """
        Retrieve all teamrooms accessible to the authenticated user
        """
        url = 'teamrooms'
        result = self.get(url)
        teamrooms = result['teamrooms']['teamroom']
        if not isinstance(teamrooms, list):
            teamrooms = [teamrooms]
        return teamrooms

    def get_snapshots(self, team_id, online='now'):
        """
        Retrieve team member snapshots

        Parameters:
          team_id   The Team ID
          online    'now' / 'last_24h' / 'all' (default 'now')
                    Filter for logged in users / users active in
                    last 24 hours / all users
        """
        url = 'snapshots/%s' % team_id
        result = self.get(url, {'online': online})
        snapshots = result['teamroom']['snapshot']
        if not isinstance(snapshots, list):
            snapshots = [snapshots]
        return snapshots

    def get_snapshot(self, company_id, user_id, datetime=None):
        """
        Retrieve a company's user snapshots during given time or 'now'

        Parameters:
          company_id    The Company ID
          user_id       The User ID
          datetime      (default 'now') Timestamp either a datetime
                        object
                        or a string in ISO 8601 format (in UTC)
                        yyyymmddTHHMMSSZ
                        or a string with UNIX timestamp (number of
                        seconds after epoch)
        """
        url = 'snapshots/%s/%s' % (str(company_id), str(user_id))
        if datetime:   # date could be a list or a range also
            url += '/%s' % datetime.isoformat()
        result = self.get(url)
        snapshot = result['snapshot']
        return snapshot

    def update_snapshot(self, company_id, user_id, datetime=None,
                        memo=''):
        """
        Update a company's user snapshot memo at given time or 'now'

        Parameters:
          company_id    The Company ID
          user_id       The User ID
          datetime      (default 'now') Timestamp either a datetime
                        object
                        or a string in ISO 8601 format (in UTC)
                        yyyymmddTHHMMSSZ
                        or a string with UNIX timestamp (number of
                        seconds after epoch)
          memo          The Memo text
        """
        url = 'snapshots/%s/%s' % (str(company_id), str(user_id))
        if datetime:
            url += '/%s' % datetime.isoformat()
        return self.post(url, {'memo': memo})

    def delete_snapshot(self, company_id, user_id, datetime=None):
        """
        Delete a company's user snapshot memo at given time or 'now'

        Parameters:
          company_id    The Company ID
          user_id       The User ID
          datetime      (default 'now') Timestamp either a datetime
                        object
                        or a string in ISO 8601 format (in UTC)
                        yyyymmddTHHMMSSZ
                        or a string with UNIX timestamp (number of
                        seconds after epoch)
        """
        url = 'snapshots/%s/%s' % (str(company_id), str(user_id))
        if datetime:
            url += '/%s' % datetime.isoformat()
        return self.delete(url)

    def get_workdiaries(self, team_id, username, date=None):
        """
        Retrieve a team member's workdiaries for given date or today

        Parameters:
          team_id       The Team ID
          username      The Team Member's username
          date          A datetime object or a string in yyyymmdd
                        format (optional)
        """
        url = 'workdiaries/%s/%s' % (str(team_id), str(username))
        if date:
            url += '/%s' % str(date)
        result = self.get(url)
        snapshots = result.get('snapshots', {}).get('snapshot', [])
        if not isinstance(snapshots, list):
            snapshots = [snapshots]
        #not sure we need to return user
        return result['snapshots']['user'], snapshots

    def get_stream(self, team_id, user_id=None,\
                   from_ts=None):
        """
        get_stream(team_id, user_id=None, from_ts=None)
        """
        url = 'streams/%s' % (team_id)
        if user_id:
            url += '/%s' % (user_id)
        if from_ts:
            data = {'from_ts': from_ts}
        else:
            data = {}
        result = self.get(url, data)
        return result['streams']['snapshot']

    def get_teamrooms_2(self):
        """
        Retrieve all teamrooms accessible to the authenticated user
        """
        url = 'teamrooms'
        self.version = 2
        result = self.get(url)
        teamrooms = result['teamrooms']['teamroom']
        if not isinstance(teamrooms, list):
            teamrooms = [teamrooms]
        self.version = 1
        return teamrooms

    def get_snapshots_2(self, team_id, online='now'):
        """
        Retrieve team member snapshots

        Parameters:
          team_id   The Team ID
          online    'now' / 'last_24h' / 'all' (default 'now')
                    Filter for logged in users / users active in
                    last 24 hours / all users
        """
        url = 'teamrooms/%s' % team_id
        self.version = 2
        result = self.get(url, {'online': online})
        snapshots = result['teamroom']['snapshot']
        if not isinstance(snapshots, list):
            snapshots = [snapshots]
        self.version = 1
        return snapshots

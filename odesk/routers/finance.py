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


class Finance(Namespace):
    api_url = 'finance/'
    version = 1

    def get_withdrawal_methods(self):
        """
        Retrieve a list of withdrawl available
        """
        return self.get('withdrawals')

    def post_withdrawal(self, method_ref, amount):
        """
        Post a withdrawl request

        Parameters
          method_ref    Withdrawl method reference
          Amount        Amount of withdrawl
        """
        url = 'withdrawals/%s' % method_ref
        data = {'amount': amount}
        return self.post(url, data)

"""
Python bindings to odesk API
python-odesk version 0.5
(C) 2010-2013 oDesk
"""
# Updated by the script
VERSION = '0.5 rc 1'


def get_version():
    return VERSION


from odesk.client import Client

__all__ = ["get_version", "Client"]

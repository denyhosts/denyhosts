import sys
import os
import time
from smtplib import SMTP

import logging

debug = logging.getLogger("util").debug

def die(msg, ex=None):
    print msg
    if ex: print ex
    sys.exit(1)


def is_true(s):
    s = s.lower()
    if s in ('1', 't', 'true', 'y', 'yes'):
        return True
    else:
        return False

def is_false(s):
    return not is_true(s)


def send_email(prefs, report_str):
    smtp = SMTP(prefs.get('SMTP_HOST'),
                prefs.get('SMTP_PORT'))

    msg = """From: %s
To: %s
Subject: %s
Date: %s

""" % (prefs.get('SMTP_FROM'),
       prefs.get('ADMIN_EMAIL'),
       prefs.get('SMTP_SUBJECT'),
       time.strftime("%a, %d %B %Y %H:%M:%S %Z"))

    msg += report_str
    try:
        smtp.sendmail(prefs.get('SMTP_FROM'),
                      prefs.get('ADMIN_EMAIL'),
                      msg)
        debug("sent email to: %s" % prefs.get("ADMIN_EMAIL"))
    except Exception, e:
        print "Error sending email"
        print e
        print "Email message follows:"
        print msg
        
    smtp.quit()

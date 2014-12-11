import logging
from smtplib import SMTP
from smtplib import SMTPResponseException
from smtplib import SMTPHeloError
import sys
from textwrap import dedent
import time
from types import IntType

from constants import BSD_STYLE, TIME_SPEC_LOOKUP
from regex import TIME_SPEC_REGEX

debug = logging.getLogger("util").debug

def setup_logging(prefs, enable_debug, verbose, daemon):
    if daemon:
        daemon_log = prefs.get('DAEMON_LOG')
        if daemon_log:
            # define a Handler which writes INFO messages or higher to the sys.stderr
            fh = logging.FileHandler(daemon_log, 'a')
            fh.setLevel(logging.DEBUG)
            formatter = logging.Formatter(prefs.get('DAEMON_LOG_MESSAGE_FORMAT'),
                prefs.get('DAEMON_LOG_TIME_FORMAT'))
            fh.setFormatter(formatter)
            # add the handler to the root logger
            logging.getLogger().addHandler(fh)
            if enable_debug:
                # if --debug was enabled provide gory activity details
                logging.getLogger().setLevel(logging.DEBUG)
                #prefs.dump_to_logger()
            else:
                # in daemon mode we always log some activity
                logging.getLogger().setLevel(logging.INFO)

            info = logging.getLogger("denyhosts").info
            info("DenyHosts launched with the following args:")
            info("   %s", ' '.join(sys.argv))
            prefs.dump_to_logger()
    else: # non-daemon
        logging.basicConfig(format="%(message)s")

        debug = logging.getLogger("denyhosts").debug
        info = logging.getLogger("denyhosts").info

        if verbose:
            logging.getLogger().setLevel(logging.INFO)
        elif enable_debug:
            logging.getLogger().setLevel(logging.DEBUG)
            debug("Debug mode enabled.")
            prefs.dump_to_logger()

def die(msg, ex=None):
    print msg
    if ex:
        print ex
    sys.exit(1)

def is_true(s):
    return s.lower() in ('1', 't', 'true', 'y', 'yes')

def is_false(s):
    return not is_true(s)

def calculate_seconds(timestr, zero_ok=False):
    # return the number of seconds in a given timestr such as 1d (1 day),
    # 13w (13 weeks), 5s (5seconds), etc...
    if type(timestr) is IntType: return timestr

    m = TIME_SPEC_REGEX.search(timestr)
    if not m:
        raise Exception("Invalid time specification: string format error: %s", timestr)

    units = int(m.group('units'))
    period = m.group('period') or 's' # seconds is the default

    if units == 0 and not zero_ok:
        raise Exception("Invalid time specification: units = 0")

    seconds = units * TIME_SPEC_LOOKUP[period]
    #info("converted %s to %ld seconds: ", timestr, seconds)
    return seconds

def parse_host(line):
    # parses a line from /etc/hosts.deny
    # returns the ip address

    # the deny file can be in the form:
    # 1) ip_address
    # 2) sshd: ip_address
    # 3) ip_address : deny
    # 4) sshd: ip_address : deny

    # convert form 3 & 4 to 1 & 2
    try:
        line = line.strip(BSD_STYLE)

        vals = line.split(":")

        # we're only concerned about the ip_address
        if len(vals) == 1:
            form = vals[0]
        else:
            form = vals[1]

        host = form.strip()
    except Exception:
        host = ""
    return host

def send_email(prefs, report_str):
    recipients = prefs['ADMIN_EMAIL'].split(',')

    msg = dedent("""
        From: %s
        To: %s
        Subject: %s
        Date: %s

        """).lstrip() % (
            prefs.get('SMTP_FROM'),
            prefs.get('ADMIN_EMAIL'),
            prefs.get('SMTP_SUBJECT'),
            time.strftime(prefs.get('SMTP_DATE_FORMAT')
        )
    )

    msg += report_str
    try:
        smtp = SMTP()

        if logging.getLogger().isEnabledFor(logging.DEBUG):
            smtp.set_debuglevel(1)

        smtp.connect(prefs.get('SMTP_HOST'),
            prefs.get('SMTP_PORT'))

        # If the server supports ESMTP and TLS, then convert the message exchange to TLS via the
        # STARTTLS command.
        if smtp.ehlo()[0] == 250:
            if smtp.has_extn('starttls'):
                (code, resp) = smtp.starttls()
                if code != 220:
                    raise SMTPResponseException(code, resp)
                (code, resp) = smtp.ehlo()
                if code != 250:
                    raise SMTPResponseException(code, resp)
        else:
            # The server does not support esmtp.

            # The Python library SMTP class handles executing HELO/EHLO commands inside
            # login/sendmail methods when neither helo()/ehlo() methods have been
            # previously called.  Because we have already called ehlo() above, we must
            # manually fallback to calling helo() here.

            (code, resp) = smtp.helo()
            if not (200 <= code <= 299):
                raise SMTPHeloError(code, resp)

        username = prefs.get('SMTP_USERNAME')
        password = prefs.get('SMTP_PASSWORD')

        if username and password:
            smtp.login(username, password)

        smtp.sendmail(prefs.get('SMTP_FROM'),
                      recipients,
                      msg)
        debug("sent email to: %s" % prefs.get("ADMIN_EMAIL"))
    except Exception, e:
        print "Error sending email"
        print e
        print "Email message follows:"
        print msg

    try:
        smtp.quit()
    except Exception:
        pass

def normalize_whitespace(string):
    return ' '.join(string.split())

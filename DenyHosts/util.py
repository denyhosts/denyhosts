import logging
import logging.handlers
from smtplib import SMTP, SMTP_SSL
from smtplib import SMTPResponseException
from smtplib import SMTPHeloError
from email.mime.text import MIMEText
from subprocess import Popen, PIPE
import sys
from textwrap import dedent
import time
py_version = sys.version_info
if py_version[0] == 2:
    # python 2
    from ipaddr import IPAddress
elif py_version[0] == 3:
    # python 3
    from ipaddress import ip_address

import re
from socket import gethostbyname

from .constants import BSD_STYLE, TIME_SPEC_LOOKUP
from .regex import TIME_SPEC_REGEX

debug = logging.getLogger("util").debug
ipv4_regex = re.compile(r'^([0-9]+\.){3}[0-9]+$')


def setup_logging(prefs, enable_debug, verbose, daemon):
        daemon_log = prefs.get('DAEMON_LOG')
        if daemon_log:
            # define a Handler which writes INFO messages or higher to the sys.stderr
            # fh = logging.FileHandler(daemon_log, 'a')
            fh = logging.handlers.RotatingFileHandler(daemon_log, 'a', 1024*1024, 7)
            fh.setLevel(logging.DEBUG)
            formatter = logging.Formatter(
                prefs.get('DAEMON_LOG_MESSAGE_FORMAT'),
                prefs.get('DAEMON_LOG_TIME_FORMAT')
            )
            fh.setFormatter(formatter)
            # add the handler to the root logger
            logging.getLogger().addHandler(fh)
            if enable_debug:
                # if --debug was enabled provide gory activity details
                logging.getLogger().setLevel(logging.DEBUG)
                # prefs.dump_to_logger()
            else:
                # in daemon mode we always log some activity
                logging.getLogger().setLevel(logging.INFO)

            info = logging.getLogger("denyhosts").info
            info("DenyHosts launched with the following args:")
            info("   %s", ' '.join(sys.argv))
            prefs.dump_to_logger()


def die(msg, ex=None):
    print(msg)
    if ex:
        print(ex)
    sys.exit(1)


def is_true(s):
    return s.lower() in ('1', 't', 'true', 'y', 'yes')


def is_false(s):
    return not is_true(s)


def calculate_seconds(timestr, zero_ok=False):
    # return the number of seconds in a given timestr such as 1d (1 day),
    # 13w (13 weeks), 5s (5seconds), etc...
    if type(timestr) is int:
        return timestr

    m = TIME_SPEC_REGEX.search(timestr)
    if not m:
        raise Exception("Invalid time specification: string format error: %s", timestr)

    units = int(m.group('units'))
    period = m.group('period') or 's'  # seconds is the default

    if units == 0 and not zero_ok:
        raise Exception("Invalid time specification: units = 0")

    seconds = units * TIME_SPEC_LOOKUP[period]
    # info("converted %s to %ld seconds: ", timestr, seconds)
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
    From: {0}
    To: {1}
    Subject: {2}
    Date: {3}

    """).lstrip().format(
        prefs.get('SMTP_FROM'),
        prefs.get('ADMIN_EMAIL'),
        prefs.get('SMTP_SUBJECT'),
        time.strftime(
            prefs.get('SMTP_DATE_FORMAT')

        )
    )

    msg += report_str
    try:
        method = prefs.get('EMAIL_METHOD')
        if is_true(prefs.get('SMTP_SSL')):
            smtp = SMTP_SSL()
        else:
            smtp = SMTP()

        if logging.getLogger().isEnabledFor(logging.DEBUG):
            smtp.set_debuglevel(1)

        smtp.connect(
            prefs.get('SMTP_HOST'),
            prefs.get('SMTP_PORT')
        )

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

            smtp.sendmail(prefs.get('SMTP_FROM'), recipients, msg)
            debug("sent email to: %s" % prefs.get("ADMIN_EMAIL"))
        elif method == 'SENDMAIL':
            msg = MIMEText(report_str)
            msg["From"] = prefs.get("SMTP_FROM")
            msg["To"] = prefs.get("ADMIN_EMAIL")
            msg["Subject"] = prefs.get("SMTP_SUBJECT")
            p = Popen(["/usr/sbin/sendmail", "-t", "-oi"], stdin=PIPE)
            p.communicate(msg.as_string())
        elif method == 'MAIL':
            p = Popen(['mail', '-s', prefs.get("SMTP_SUBJECT")] + recipients, stdin=PIPE)
            p.communicate(report_str)
        elif method == 'STDOUT':
            print(report_str)
        else:
            raise Exception("Unknown e-mail method: %s" % method)
    except Exception as e:
        print("Error sending email")
        print(e)
        print("Email message follows:")
        print(report_str)

    try:
        smtp.quit()
    except Exception:
        pass


def normalize_whitespace(string):
    return ' '.join(string.split())

def hostname_lookup(process_host):
    if re.match(ipv4_regex, process_host):
        return process_host
    ip = gethostbyname(process_host)
    return ip

def is_valid_ip_address(process_ip):
    ip = None
    if py_version[0] == 2:
        # python 2
        ip = IPAddress(process_ip)
    elif py_version[0] == 3:
        # python 3
        ip = ip_address(process_ip)

    if ip is None or ip.is_reserved or ip.is_private or \
            ip.is_loopback or ip.is_unspecified or \
            ip.is_multicast or ip.is_link_local:
        return False
    return True


def get_user_input(prompt):
    try:
        response = raw_input(prompt)
    except NameError:
        response = input(prompt)
    return response

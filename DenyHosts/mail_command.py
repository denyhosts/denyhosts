# coding=utf-8
import shlex
import subprocess


def send_mail_by_command(mail_command, recipients, data, logger):
    command_to_exec = shlex.split(mail_command) + recipients
    if logger:
        logger("sent email using command: %s" % command_to_exec)
    try:
        process = subprocess.Popen(command_to_exec, stdin=subprocess.PIPE)
    except OSError as err:
        if logger:
            logger("There was an error: %s" % err)
        return -1
    process.communicate(data)
    return process.wait()

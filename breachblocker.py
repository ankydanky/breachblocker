# coding: utf-8

import os
import sys
import re
import socket
import syslog
import sqlite3
import tempfile
import datetime
import time
import subprocess
import signal
import traceback
import argparse
import getpass
import configparser

from collections import defaultdict


"""
==================================================
**BREACHBLOCKER**

Breachblocker is a script designed to crawl log files
and get the ip addresses of hosts which tried to
break in

Copyright (C) Andy Kayl - All Rights Reserved
* Unauthorized copying of this file, via any medium is prohibited, except for your own needs
* Modification to the script logic is also prohibited, except for your own needs
* Licencing to a third-party is strictly prohibited
* Selling this script is strictly prohibited, this script is always free of charge
* Using in closed source software without prior confirmation of the author is strictly prohibited
* The author declines any responsability for any damage of any nature this script could cause

Written by Andy Kayl <andy@ndk.sytes.net>, August 2013
==================================================
"""

__author__ = "Andy Kayl"
__version__ = "2.5.0"
__modified__ = "2019-10-05"

"""---------------------------
check python version before running
---------------------------"""
    
major = sys.version_info[0]
minor = sys.version_info[1]

if (major < 3 and minor < 5):
    print("You need Python 3.5+ to run this script")
    sys.exit(1)

IS_PY3 = False
if major == 3:
    IS_PY3 = True

"""---------------------------
load mailer for simplified email sending
---------------------------"""

try:
    import mailer
except ImportError:
    print("Python mailer module is needed. Please install it with: pip install mailer")
    sys.exit(1)

"""---------------------------
define default config variables
---------------------------"""

dry_run = 1
daemon = 0
pid_file = "/var/run/breachblocker.pid"
scan_interval = 10
write_syslog = 1
attempts = 10
block_timeout = 60
history_timeout = 43200
whitelist = "127.0.0.1"
blacklist = ""
dbfile = "/tmp/breachblocker.db"

scan_http = 0
scan_ssh = 0
scan_ftp = 0
scan_mail = 0
scan_smtp = 0

send_email = 0
mailhost = "127.0.0.1"
    
"""---------------------------
load config
---------------------------"""

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), "breachblocker.conf"))

if config.has_option("global", "dry_run"):
    dry_run = config.getint("global", "dry_run")
if config.has_option("global", "daemon"):
    daemon = config.getint("global", "daemon")
if config.has_option("global", "scan_interval"):
    scan_interval = config.getint("global", "scan_interval")
if config.has_option("global", "pid_file"):
    pid_file = config.get("global", "pid_file")
if config.has_option("global", "write_syslog"):
    write_syslog = config.getint("global", "write_syslog")
if config.has_option("global", "attempts"):
    attempts = config.getint("global", "attempts")
if config.has_option("global", "block_timeout"):
    block_timeout = config.getint("global", "block_timeout")
if config.has_option("global", "history_timeout"):
    history_timeout = config.getint("global", "history_timeout")
if config.has_option("global", "whitelist"):
    whitelist = config.get("global", "whitelist")
if config.has_option("global", "blacklist"):
    blacklist = config.get("global", "blacklist")
if config.has_option("global", "db_file"):
    dbfile = config.get("global", "db_file")

if config.has_option("scan", "http"):
    scan_http = config.getint("scan", "http")
if config.has_option("scan", "ssh"):
    scan_ssh = config.getint("scan", "ssh")
if config.has_option("scan", "ftp"):
    scan_ftp = config.getint("scan", "ftp")
if config.has_option("scan", "mail"):
    scan_mail = config.getint("scan", "mail")
if config.has_option("scan", "smtp"):
    scan_smtp = config.getint("scan", "smtp")

http_svr = config.get("servers", "http")
ftp_svr = config.get("servers", "ftp")
mail_svr = config.get("servers", "mail")
ssh_svr = config.get("servers", "ssh")
smtp_svr = config.get("servers", "smtp")

if config.has_option("email", "send"):
    send_email = config.getint("email", "send")
if config.has_option("email", "mailhost"):
    mailhost = config.get("email", "mailhost")
email_from = config.get("email", "from")
email_to = config.get("email", "recipient")

"""---------------------------
supported server list
---------------------------"""

supp_servers = {
    "rhel": [
        "apache", "dovecot", "uw-imapd", "openssh",
        "postfix", "proftpd", "pure-ftpd", "vsftpd"
    ],
    "freebsd": [
        "apache", "dovecot", "openssh", "postfix", "proftpd"
    ]
}

"""---------------------------
add cli arguments
---------------------------"""

parser = argparse.ArgumentParser()
parser.add_argument("--kill", help="Kill runniing process (only in daemon mode)", action="store_true")
parser.add_argument("--single", help="Run this script once if daemon mode is set to yes", action="store_true")
parser.add_argument("--daemon", help="Launch as background daemon", action="store_true")
parser.add_argument("--remove", help="Specify an ip address to remove from firewall", metavar="IPv4-ADDR")
parser.add_argument("--check", help="Specify an ip address to check in white-/blacklist/firewall", metavar="IPv4-ADDR")
parser.add_argument(
    "--whitelist",
    help="Specify an ip address to whitelist temporary (minutes)",
    nargs=2,
    metavar=("MIN", "IPv4-ADDR")
)
parser.add_argument("--bl", help="List all blocked ip addresses during scans", action="store_true")
parser.add_argument("--wl", help="List all temporary whitelisted addresses", action="store_true")
parser.add_argument("--flush", help="Clear all database/firewall adresses", action="store_true")
parser.add_argument("--no-dryrun", help="Overwrite config setting for DRY-RUN", action="store_true")
parser.add_argument("--history", help="Show history entries", action="store_true")


class Firewall(object):
    """ Firewall class: used for firewall interactions """

    def __init__(self):
        """ init firewall stuff """

        self._ipfw_rulestable = 100
        
        self.iptables_version = None
        self.firewall_type = config.get("global", "firewall")
        self.firewall = None
        
        self._detect()
    
    def _detect(self):
        """ detect firewall type and return it / store it inside class """

        if self.firewall_type == "iptables":
            self.firewall = "iptables"
        elif self.firewall_type == "firwalld":
            self.firewall = "firewalld"
        elif self.firewall_type == "ipfw":
            self.firewall = "ipfw"
        else:
            if os.path.isfile("/sbin/ipfw"):
                self.firewall = "ipfw"
            elif os.path.isfile("/usr/bin/firewall-cmd"):
                self.firewall = "firewalld"
            elif os.path.isfile("/sbin/iptables"):
                self.firewall = "iptables"
            else:
                print("Could not determine firewall type. Please set it manually.")
                sys.exit(1)
        
        if self.firewall == "iptables":
            proc = subprocess.Popen("/sbin/iptables --version", shell=True, stdout=subprocess.PIPE)
            proc.wait()
            proc_out = proc.communicate()[0]
            if IS_PY3:
                proc_out = proc_out.decode()
            (major, minor, bugfix) = proc_out.replace("v", "").strip().split(" ")[1].split(".")
            self.iptables_version = "%d.%02d.%02d" % (int(major), int(minor), int(bugfix))
    
    def add(self, ip):
        """ add the given ip to the system firewall rules """
        
        if self.firewall == "firewalld":
            proc = subprocess.Popen(
                "/usr/bin/firewall-cmd --quiet --zone drop --add-source %s" % ip,
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            proc.wait()
        
        elif self.firewall == "ipfw":
            proc = subprocess.Popen(
                "/sbin/ipfw list | grep '00001 deny ip from table(%d)'" % self._ipfw_rulestable,
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            proc.wait()
            stdout = proc.communicate()[0]
            if stdout == "":
                proc = subprocess.Popen(
                    "/sbin/ipfw -q add 1 deny ip from 'table(%d)' to any" % self._ipfw_rulestable,
                    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
                proc.wait()
            proc = subprocess.Popen(
                "/sbin/ipfw -q table %d add %s" % (self._ipfw_rulestable, ip),
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            proc.wait()
        
        else:
            cmd = "/sbin/iptables -w -I INPUT -s %s -j DROP"
            if self.iptables_version and self.iptables_version < "1.04.20":
                cmd = "/sbin/iptables -I INPUT -s %s -j DROP"
            proc = subprocess.Popen(cmd % ip, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.wait()

        return proc.returncode
    
    def getBlocked(self):
        """ get all addresses blocked by the firewall """

        fw_source_blocked = []

        if self.firewall == "firewalld":
            proc = subprocess.Popen(
                "/usr/bin/firewall-cmd --zone drop --list-sources",
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            proc.wait()
            blocked = proc.communicate()[0]
            if IS_PY3:
                blocked = blocked.decode()
            blocked = re.split("\s{1,}", blocked)
            for entry in blocked:
                if entry == "":
                    continue
                fw_source_blocked.append(entry)
        
        elif self.firewall == "ipfw":
            proc = subprocess.Popen(
                "/sbin/ipfw table %d list" % self._ipfw_rulestable,
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            proc.wait()
            blocked = proc.communicate()[0]
            if IS_PY3:
                blocked = blocked.decode()
            blocked = blocked.split("\n")
            for entry in blocked:
                if entry == "":
                    continue
                line = re.split("\s{1,}", entry)
                host = line[0].replace("/32", "")
                fw_source_blocked.append(host)
        
        else:
            cmd = "/sbin/iptables -w -L INPUT -n | grep DROP"
            if self.iptables_version and self.iptables_version < "1.04.20":
                cmd = "/sbin/iptables -L INPUT -n | grep DROP"
            blocked = os.popen(cmd).readlines()
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.wait()
            stdout = proc.communicate()[0]
            if IS_PY3:
                stdout = stdout.decode()
            blocked = stdout.rstrip().split("\n")
            for entry in blocked:
                if entry == "":
                    continue
                line = re.split("\s{1,}", entry)
                if len(line) < 5:
                    continue
                fw_source_blocked.append(line[3])
        
        return fw_source_blocked
    
    def remove(self, ip):
        """ remove given ip address from the firewall rules """

        if self.firewall == "firewalld":
            proc = subprocess.Popen(
                "/usr/bin/firewall-cmd --quiet --zone drop --remove-source %s" % ip,
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            proc.wait()
        
        elif self.firewall == "ipfw":
            proc = subprocess.Popen(
                "/sbin/ipfw table %d list | grep %s" % (self._ipfw_rulestable, ip),
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            proc.wait()
            stdout, stderr = proc.communicate()
            if stdout == "":
                return
            stdout = stdout.decode()
            ip = re.split("\s+", stdout)[0]
            proc = subprocess.Popen(
                "/sbin/ipfw -q table %d delete %s" % (self._ipfw_rulestable, ip),
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            proc.wait()
        
        else:
            cmd = "/sbin/iptables -w -D INPUT -s %s -j DROP"
            if self.iptables_version and self.iptables_version < "1.04.20":
                cmd = "/sbin/iptables -D INPUT -s %s -j DROP"
            proc = subprocess.Popen(
                cmd % ip,
                shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            proc.wait()
        
        return proc.returncode
    
    def check(self, ip):
        fw_blocked = self.getBlocked()
        if ip in fw_blocked:
            return True
        return False


class BreachBlocker(object):
    """ Breachblocker main class """

    @staticmethod
    def initDB():
        """ init SQLite database and fetch data """
        
        dbconn = sqlite3.connect(config.get("global", "db_file"))
        dbcursor = dbconn.cursor()
        dbcursor.execute("CREATE TABLE IF NOT EXISTS addresses (ip, date, reason)")
        dbcursor.execute("CREATE TABLE IF NOT EXISTS whitelist (ip, date)")
        dbcursor.execute("CREATE TABLE IF NOT EXISTS history (ip, date)")
        try:
            dbcursor.execute("ALTER TABLE addresses ADD COLUMN reason")
        except sqlite3.OperationalError as e:
            pass
        dbconn.commit()
        dbconn.close()
    
    def __init__(self):
        """ Init breachblocker class, set config params, detect firewall and more """
        
        self.write_syslog = write_syslog

        self.firewall = Firewall().firewall
        self.mode = None
        self.rules = None

        self._blk_reason = {
            "ssh": [],
            "ftp": [],
            "mail": [],
            "smtp": [],
            "http": [],
            "blacklist": [],
        }
        self._fw_updated = False
    
    def printError(self, string):
        """ Prints and logs error message """

        print("ERROR: %s" % string)
        if self.write_syslog:
            syslog.syslog(syslog.LOG_ERR, string)
        sys.exit(1)
    
    def checkOS(self):
        """ check for correct os version """
        
        rel_file = "/etc/redhat-release"
        
        found_centos = False
        if os.path.isfile(rel_file):
            file_content = open(rel_file).readline()
            found_centos = re.search("centos( linux)? release (6|7)", file_content, re.IGNORECASE)
        
        found_freebsd = re.search("freebsd(10|11|12)", sys.platform, re.IGNORECASE)
        
        if not found_centos and not found_freebsd:
            self.printError(
                "Operating System is invalid. " +
                "This script runs only on RHEL/CentOS Linux version 6/7 or FreeBSD 10/11/12"
            )
        
        if found_centos:
            self.mode = "rhel"
        elif found_freebsd:
            self.mode = "freebsd"
    
    def loadRules(self):
        """ load rules from directory """

        nosupp = "The specified server/rules (%s) is/are not supported on this OS."
        
        if http_svr not in supp_servers[self.mode]:
            self.printError(nosupp % http_svr)
        if mail_svr not in supp_servers[self.mode]:
            self.printError(nosupp % mail_svr)
        if smtp_svr not in supp_servers[self.mode]:
            self.printError(nosupp % smtp_svr)
        if ftp_svr not in supp_servers[self.mode]:
            self.printError(nosupp % ftp_svr)
        if ssh_svr not in supp_servers[self.mode]:
            self.printError(nosupp % ssh_svr)
        
        self.rules = {
            "http": self._parseRule(self.mode, http_svr),
            "mail": self._parseRule(self.mode, mail_svr),
            "smtp": self._parseRule(self.mode, smtp_svr),
            "ftp": self._parseRule(self.mode, ftp_svr),
            "ssh": self._parseRule(self.mode, ssh_svr)
        }
    
    def _parseRule(self, osname, svrname):
        """ parse the given rule and return dict """

        rulesdir = os.path.abspath(os.path.dirname(__file__))
        ruleconf = configparser.ConfigParser()
        ruleconf.read(os.path.join(rulesdir, "rules", "%s_%s.conf" % (osname, svrname)))
        
        return {
            "rc": re.split("\s{1,}|\n", ruleconf.get("rule", "rc")),
            "log": ruleconf.get("rule", "log"),
            "regex_fail": ruleconf.get("rule", "regex_fail"),
            "regex_host": ruleconf.get("rule", "regex_host"),
        }
    
    def testRC(self, ruletype):
        """ test for existing server binary used in ruleset """

        conf = self.rules[ruletype]
        if conf["rc"] is None or conf['rc'] == "":
            return True
        for entry in conf['rc']:
            if os.path.isfile(entry):
                return True
        return False
    
    def checkSoftware(self):
        """ check for invalid defined servers """

        errormsg = ""
        
        websvr_found = False
        mailsvr_found = False
        smtpsvr_found = False
        ftpsvr_found = False
        sshsvr_found = False
        
        if scan_http:
            websvr_found = self.testRC("http")
            if not websvr_found:
                errormsg += "Web server not found: " + http_svr + "\n"
        
        if scan_mail:
            mailsvr_found = self.testRC("mail")
            if not mailsvr_found:
                errormsg += "POP/IMAP server not found: " + mail_svr + "\n"
        
        if scan_smtp:
            smtpsvr_found = self.testRC("smtp")
            if not smtpsvr_found:
                errormsg += "SMTP server not found: " + smtp_svr + "\n"
        
        if scan_ftp:
            ftpsvr_found = self.testRC("ftp")
            if not ftpsvr_found:
                errormsg += "FTP server not found: " + ftp_svr + "\n"
        
        if scan_ssh:
            sshsvr_found = self.testRC("ssh")
            if not sshsvr_found:
                errormsg += "SSH server not found: " + ssh_svr + "\n"
        
        if errormsg != "":
            
            errormsg += "\n"
            errormsg += "Supported servers on this platform:\n"
            for entry in supp_servers[self.mode]:
                errormsg += "\t- %s\n" % entry
            self.printError(errormsg)
            
        else:
            
            self.http_svr_data = {
                "log": self.rules['http']['log'],
                "log_pattern": self.rules['http']['regex_fail'],
                "ip_pattern": self.rules['http']['regex_host']
            }
            self.mail_svr_data = {
                "log": self.rules['mail']['log'],
                "log_pattern": self.rules['mail']['regex_fail'],
                "ip_pattern": self.rules['mail']['regex_host']
            }
            self.smtp_svr_data = {
                "log": self.rules['smtp']['log'],
                "log_pattern": self.rules['smtp']['regex_fail'],
                "ip_pattern": self.rules['smtp']['regex_host']
            }
            self.ftp_svr_data = {
                "log": self.rules['ftp']['log'],
                "log_pattern": self.rules['ftp']['regex_fail'],
                "ip_pattern": self.rules['ftp']['regex_host']
            }
            self.ssh_svr_data = {
                "log": self.rules['ssh']['log'],
                "log_pattern": self.rules['ssh']['regex_fail'],
                "ip_pattern": self.rules['ssh']['regex_host']
            }
    
    def checkLogfiles(self):
        """ check if the specified log files do exist """
        
        if self.http_svr_data and scan_http:
            if not os.path.isfile(self.http_svr_data['log']):
                self.printError("HTTP log file " + self.http_svr_data['log'] + " not found")
        
        if self.ftp_svr_data and scan_ftp:
            if not os.path.isfile(self.ftp_svr_data['log']):
                self.printError("FTP log file " + self.ftp_svr_data['log'] + " not found")
        
        if self.ssh_svr_data and scan_ssh:
            if not os.path.isfile(self.ssh_svr_data['log']):
                self.printError("SSH log file " + self.ssh_svr_data['log'] + " not found")
        
        if self.mail_svr_data and scan_mail:
            if not os.path.isfile(self.mail_svr_data['log']):
                self.printError("MAIL log file " + self.mail_svr_data['log'] + " not found")
        
        if self.smtp_svr_data and scan_smtp:
            if not os.path.isfile(self.smtp_svr_data['log']):
                self.printError("SMTP log file " + self.smtp_svr_data['log'] + " not found")
    
    def _checkLogTimeout(self, line):
        """ check log entry line timeout """

        if line == "":
            return False

        now_in_secs = int(time.time())
        ignore_timeout = 3600
        block_timeout = config.getint("global", "block_timeout") * 60

        if block_timeout < ignore_timeout:
            ignore_timeout = block_timeout
        
        line_arr = re.split("\s{1,}", line)
        (month_name, day, time_) = line_arr[0:3]
        year = datetime.datetime.now().strftime("%Y")
        
        timeout_date = datetime.datetime.strptime("%s %s %s %s" % (year, month_name, day, time_), "%Y %b %d %H:%M:%S")
        timeout_date_tuple = timeout_date.timetuple()
        timeout_in_sec = int(time.mktime(timeout_date_tuple))
        
        if now_in_secs - timeout_in_sec <= ignore_timeout:
            return True
        
        return False
    
    def scan(self):
        """ do the hard work, scan files for intruders """

        print("Scanning for IPs to block... ", end="", flush=True)
        
        now_in_secs = int(time.time())
        line_numbers = 100
        ip_list = []
        
        self._ips_to_block = []
        self._blk_cause = self._blk_reason
        
        if self.ssh_svr_data and scan_ssh:
            ssh_comm = "cat %s | grep -i sshd | grep -i -E \"%s\" | tail -n %s" % (
                self.ssh_svr_data['log'], self.ssh_svr_data['log_pattern'], line_numbers
            )
            proc = subprocess.Popen(ssh_comm, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.wait()
            (stdout, stderr) = proc.communicate()
            if IS_PY3:
                stdout = stdout.decode()
            shell_ret = stdout.rstrip().split("\n")
            for i in shell_ret:
                if not self._checkLogTimeout(i):
                    continue
                match = re.search(self.ssh_svr_data['ip_pattern'], i, re.IGNORECASE)
                if match:
                    match = match.group()
                    if "=" in match:
                        ip = match.rstrip().split("=")[1]
                    elif "from " in match:
                        ip = match.replace("from ", "")
                    ip_list.append(ip)
                    self._blk_reason['ssh'].append(ip)
        
        if self.mail_svr_data and scan_mail:
            mail_comm = "cat %s | " % self.mail_svr_data['log']
            mail_comm += "grep -i -E \"(imap|pop3)\" | "
            mail_comm += "grep -E -v \"user=<>\" | "
            mail_comm += "grep -i -E \"%s\" | " % self.mail_svr_data['log_pattern']
            mail_comm += "tail -n %s" % line_numbers
            proc = subprocess.Popen(mail_comm, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.wait()
            (stdout, stderr) = proc.communicate()
            if IS_PY3:
                stdout = stdout.decode()
            shell_ret = stdout.rstrip().split("\n")
            for i in shell_ret:
                if not self._checkLogTimeout(i):
                    continue
                match = re.search(self.mail_svr_data['ip_pattern'], i, re.IGNORECASE)
                if match:
                    match = match.group()
                    ip = match.rstrip().split("=")
                    ip_list.append(ip[1])
                    self._blk_reason['mail'].append(ip[1])
        
        if self.smtp_svr_data and scan_smtp:
            smtp_comm = "cat %s | " % self.smtp_svr_data['log']
            smtp_comm += "grep -i -E \"(smtp|sasl)\" | "
            smtp_comm += "grep -i -E -v \"Connection lost\" | "
            smtp_comm += "grep -i -E \"%s\" | " % self.smtp_svr_data['log_pattern']
            smtp_comm += "tail -n %s" % line_numbers
            proc = subprocess.Popen(smtp_comm, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.wait()
            (stdout, stderr) = proc.communicate()
            if IS_PY3:
                stdout = stdout.decode()
            shell_ret = stdout.rstrip().split("\n")
            for i in shell_ret:
                if not self._checkLogTimeout(i):
                    continue
                match = re.search(self.smtp_svr_data['ip_pattern'], i, re.IGNORECASE)
                if match:
                    match = match.group()
                    if smtp_svr == "postfix":
                        ip = re.sub("(\[|\])", "", match)
                    else:
                        ip = match.rstrip().split("=")[1]
                    ip_list.append(ip)
                    self._blk_reason['smtp'].append(ip)
        
        if self.ftp_svr_data and scan_ftp:
            ftp_comm = "cat %s | grep -i ftpd | grep -i -E \"%s\" | tail -n %s" % (
                self.ftp_svr_data['log'], self.ftp_svr_data['log_pattern'], line_numbers
            )
            proc = subprocess.Popen(ftp_comm, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.wait()
            (stdout, stderr) = proc.communicate()
            if IS_PY3:
                stdout = stdout.decode()
            shell_ret = stdout.rstrip().split("\n")
            for i in shell_ret:
                if not self._checkLogTimeout(i):
                    continue
                match = re.search(self.ftp_svr_data['ip_pattern'], i, re.IGNORECASE)
                if match:
                    match = match.group()
                    if ftp_svr == "proftpd":
                        ip = re.sub("(::ffff:|\[|\])", "", match)
                    elif ftp_svr == "vsftpd":
                        ip = match.rstrip().split("=")
                        ip = ip[1]
                    elif ftp_svr == "pure-ftpd":
                        ip = re.sub("\?@", "", match)
                    ip_list.append(ip)
                    self._blk_reason['ftp'].append(ip)
        
        if self.http_svr_data and scan_http:
            http_comm = "cat %s | grep -i -E \"%s\" | tail -n %s" % (
                self.http_svr_data['log'], self.http_svr_data['log_pattern'], line_numbers
            )
            proc = subprocess.Popen(http_comm, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            proc.wait()
            (stdout, stderr) = proc.communicate()
            if IS_PY3:
                stdout = stdout.decode()
            shell_ret = stdout.rstrip().split("\n")
            for i in shell_ret:
                if not self._checkLogTimeout(i):
                    continue
                if "favicon" not in shell_ret:
                    match = re.search(self.http_svr_data['ip_pattern'], i, re.IGNORECASE)
                    if match:
                        match = match.group()
                        ip = match.lstrip("client ")
                        ip_list.append(ip)
                        self._blk_reason['http'].append(ip)
        
        unique_ip_counts = defaultdict(int)
        for x in ip_list:
            unique_ip_counts[x] += 1
        for ip, num in unique_ip_counts.items():
            if num > attempts:
                self._ips_to_block.append(ip)
        
        for ip in self._getBlacklistAddresses():
            self._ips_to_block.append(ip)
            self._blk_cause['blacklist'].append(ip)
        
        for key, value in self._blk_reason.items():
            unique_ip_counts = defaultdict(int)
            for x in value:
                unique_ip_counts[x] += 1
            for ip in unique_ip_counts:
                try:
                    ip = socket.gethostbyname(ip)
                    self._blk_cause[key].append(ip)
                except Exception as e:
                    pass
        
        print("\033[32mdone.\033[0m")
    
    def _getBlacklistAddresses(self):
        """ get blacklisted ip addresses from config """

        if blacklist == "":
            return []
        blist = blacklist
        if blacklist.startswith("file:"):
            filename = blacklist.replace("file:", "")
            if not os.path.isfile(filename):
                raise FileNotFoundError("Could not find blacklist: {file}".format(file=filename))
            blist = open(filename, "r").read()
        blist = re.split("\s{1,}|\n", blist.strip())
        return blist
    
    def _checkWhitelist(self, host):
        """ check if host is in config whitelist """

        if whitelist == "":
            return False
        wlist = whitelist
        if whitelist.startswith("file:"):
            filename = whitelist.replace("file:", "")
            if not os.path.isfile(filename):
                raise FileNotFoundError("Could not find whitelist: {file}".format(file=filename))
            wlist = open(filename, "r").read()
        wlist = re.split("\s{1,}|\n", wlist.strip())
        for wl in wlist:
            ip_found = False
            if wl == host:
                ip_found = True
            else:
                try:
                    ip = socket.gethostbyname(host)
                    if wl == ip:
                        ip_found = True
                except Exception:
                    pass
            if ip_found:
                print("%s found in whitelist... skipping..." % host)
                return True
        return False
    
    def _checkDatabaseWhitelist(self, host):
        """ check if host ip is in the temp whitelist db table """
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror as e:
            return False
        qry = self.dbcursor.execute(
            "SELECT ip FROM whitelist WHERE ip=? AND date>date('now')",
            (ip,)
        )
        res_wl = qry.fetchall()
        for row in res_wl:
            if row[0] == ip:
                return True
        return False
    
    def _getHostAddress(self, host):
        """ find host address from host name/dns """
        try:
            return socket.gethostbyname(host)
        except Exception as e:
            return None
    
    def _updateDueToViolations(self):
        """ update the firewall and add block entries to the database """

        print("Updating firewall... ", end="", flush=True)
        
        new_ips = []
        ip_violations = {}
        
        for host in self._ips_to_block:
            is_in_conf_wl = self._checkWhitelist(host)
            is_in_db_wl = self._checkDatabaseWhitelist(host)
            if not is_in_conf_wl and not is_in_db_wl:
                if re.search("/\d{1,2}$", host):
                    ip = host
                else:
                    ip = self._getHostAddress(host)
                if ip is not None and ip not in self._fw_source_blocked:
                    new_ips.append(ip)
        
        self._new_ips = new_ips
        
        if len(new_ips) > 0:
            
            for ip in new_ips:
                
                for key, value in self._blk_cause.items():
                    if ip in value:
                        if ip_violations.get(ip) is None:
                            ip_violations[ip] = list()
                        ip_violations[ip].append(key)
                
                self._ip_violations = ip_violations
                
                violations = ", ".join(ip_violations[ip])
                
                print("\n\033[31mBlocking host %s (%s)\033[0m" % (ip, violations), end="", flush=True)
                
                if dry_run:
                    continue
                
                if Firewall().add(ip) == 0:
                    if ip not in self._getBlacklistAddresses():
                        self.dbcursor.execute(
                            "INSERT INTO addresses (ip, date, reason) VALUES (?, DATETIME('now', 'localtime'), ?)",
                            (ip, violations)
                        )
                        self.dbcursor.execute(
                            "INSERT INTO history (ip, date) VALUES (?, DATETIME('now', 'localtime'))",
                            (ip,)
                        )
                        self.dbconn.commit()
                    if self.write_syslog:
                        syslog.syslog(
                            syslog.LOG_NOTICE, "IP " + ip + " was blocked due to " + violations + " violation"
                        )
                    self._fw_updated = True
                else:
                    self.printError("Sorry. error when updating firewall (violations)...")
            
        else:
            print("\033[32mNo threats found.\033[0m")
    
    def _getFirewallInputRules(self):
        """ get all blocked ip addresses """
        self._fw_source_blocked = Firewall().getBlocked()
    
    def _removeAddressFromFirewall(self, ip):
        """ remove ip from firewall """
        returncode = Firewall().remove(ip)
        if returncode == 0 and self.write_syslog:
            syslog.syslog(
                syslog.LOG_NOTICE,
                "IP %s was removed due to block timeout (%s minutes)" % (ip, block_timeout)
            )
    
    def _removeOutdatedBlocklist(self):
        """ remove outdated/timed out addresses """

        print("Removing old blocked ip addresses... ", end="")
        
        if block_timeout == 0:
            print("\033[33mdisabled.\033[0m")
            return
        
        count_remove = 0
        
        for row in self.ip_rows:
            res_history_ip = self.dbcursor.execute(
                "SELECT COUNT(ip) AS cnt FROM history WHERE ip=?",
                (row[0],)
            ).fetchall()

            unix_stamp = int(time.time()) - (block_timeout * 60)
            if res_history_ip[0][0] > 1:
                timeout_sec = 1210
                if block_timeout > 1220:
                    timeout_sec = block_timeout
                unix_stamp = int(time.time()) - (timeout_sec * 60 * int(res_history_ip[0][0]))
            
            deadline = datetime.datetime.fromtimestamp(unix_stamp).strftime("%Y-%m-%d %H:%M:%S")
            
            if row[1] < deadline:
                if not dry_run:
                    self.dbcursor.execute("DELETE FROM addresses WHERE ip=?", (row[0],))
                    if row[0] in self._fw_source_blocked:
                        self._removeAddressFromFirewall(row[0])
                count_remove += 1
        
        if count_remove > 0:
            if not dry_run:
                self.dbconn.commit()
            print("\033[32m%d addresses removed.\033[0m" % count_remove)
        else:
            print("\033[32mdone.\033[0m")
    
    def _removeOutdatedWhitelist(self):
        """ remove timed out entries from whitelist """
        date = time.strftime("%Y-%m-%d %H:%M:%S")
        print("Removing old whitelisted ip addresses... ", end="")
        self.dbcursor.execute("DELETE FROM whitelist WHERE date<?", (date,))
        self.dbconn.commit()
        print("\033[32mdone.\033[0m")
    
    def _getDatabaseData(self):
        """ get blocked addresses from database """
        self.ip_rows = self.dbcursor.execute("SELECT ip, date FROM addresses").fetchall()
    
    def clear(self):
        """ cleanup database entries """
        if dry_run:
            return
        self.dbcursor.execute("DELETE FROM addresses")
        self.dbconn.commit()
    
    def clearOldHistory(self):
        """ clear old history from database """
        timeout = history_timeout
        if timeout == 0:
            return
        if timeout < block_timeout:
            timeout = block_timeout
        self.dbcursor.execute(
            """
            DELETE FROM history
            WHERE date<DATE('now', '-{0} seconds')
            """.format(timeout)
        )
        self.dbconn.commit()
    
    def updateFirewall(self):
        """ update firewall (wrapper function) """
        self._fw_updated = False
        self._getDatabaseData()
        self._getFirewallInputRules()
        self._removeOutdatedBlocklist()
        self._removeOutdatedWhitelist()
        self._updateDueToViolations()
        print("")
        if self._fw_updated is True:
            print("Firewall updated...")
    
    def sendNotif(self):
        """ send out mail """

        if not self._fw_updated or not send_email:
            return
        print("Sending notification email...")
        message = mailer.Message(
            From=email_from,
            To=re.split("\s{1,}|\n", email_to),
            Subject="BreachBlocker Notification"
        )
        message.Body = ""
        for ip in self._new_ips:
            message.Body += "Host " + ip + " added to firewall droplist (" + ", ".join(self._ip_violations[ip]) + ")\n"
        sender = mailer.Mailer(mailhost)
        try:
            sender.send(message)
        except Exception:
            self.printError("Could not send email. Server problems?")
    
    def kill(self):
        """ kill the daemon """
        try:
            pid = open(pid_file, "r").read().strip()
            os.unlink(pid_file)
            os.kill(int(pid), 9)
            print("Daemon killed (%s)..." % pid)
        except Exception as e:
            print(str(e))
    
    def run(self):
        """ run the script """
        self.checkOS()
        self.loadRules()
        self.checkSoftware()
        self.checkLogfiles()
        self.dbconn = sqlite3.connect(dbfile)
        self.dbcursor = self.dbconn.cursor()
        self.clearOldHistory()
        self.scan()
        self.updateFirewall()
        self.sendNotif()
        self.dbconn.close()
            

class BBCli(BreachBlocker):
    """ CLI interface class for Breachblocker """

    def __init__(self):
        """ init cli interface """
        BreachBlocker.__init__(self)
        self.initDB()
        self.dbconn = sqlite3.connect(dbfile)
        self.dbcursor = self.dbconn.cursor()
    
    def __del__(self):
        """ cleanup on del """
        self.dbconn.close()
    
    def _checkIpFormat(self, ip):
        """ test if given ip has the correct IPv4 format """
        if re.search("^(\d{1,3}\.){3}\d{1,3}$", ip):
            return True
        print("Specified IP format is wrong.")
        return False
    
    def _getHostAddress(self, host):
        """ get ip address for hostname """
        ip = host
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            print("Could not resolve host address...")
            sys.exit(1)
        return ip
    
    def remove(self, ip):
        """ remove the given ip from database and firewall """
        if not self._checkIpFormat(ip):
            sys.exit(1)
        retcode = 0
        print("Removing %s from firewall... " % ip, end="")
        fw = Firewall()
        fw_blocked = fw.getBlocked()
        if ip not in fw_blocked:
            print("\033[33mIP %s not in firewall.\033[0m" % ip)
        else:
            if not dry_run:
                retcode = Firewall().remove(ip)
        if retcode == 0:
            print("\033[32mdone.\033[0m")
        else:
            print("\033[31merror.\033[0m")
        print("Removing %s from database... " % ip, end="")
        if not dry_run:
            self.dbcursor.execute("DELETE FROM addresses WHERE ip=?", (ip,))
            self.dbconn.commit()
        print("\033[32mdone.\033[0m")
        CliLogger.write("command remove executed by %s for %s" % (getpass.getuser(), ip))
              
    def flush(self):
        """ flush all data (firewall, blocked hosts) """
        self._getDatabaseData()
        fw = Firewall()
        for row in self.ip_rows:
            print("Removing %s from firewall... " % row[0], end="", flush=True)
            if not dry_run:
                retcode = fw.remove(row[0])
                if retcode != 0:
                    print("error.", flush=True)
                    continue
            print("done.", flush=True)
        self.clear()
        print("Firewall and blocklist cleared.", flush=True)
        CliLogger.write("command flush executed by %s" % getpass.getuser())
    
    def wlist(self, minutes, host):
        """ add an <ip> address for <minutes> to the whitelist dataabase """
        ip = self._getHostAddress(host)
        if not self._checkIpFormat(ip):
            sys.exit(1)
        minutes = int(minutes)
        date_deadline = datetime.datetime.fromtimestamp(int(time.time()) + minutes * 60)
        res_wl = self.dbcursor.execute("SELECT ip, date FROM whitelist WHERE ip=?", (ip,)).fetchall()
        if len(res_wl) == 0:
            self.dbcursor.execute("INSERT INTO whitelist (ip, date) VALUES (?, ?)", (ip, date_deadline))
        else:
            self.dbcursor.execute("UPDATE whitelist SET date=? WHERE ip=?", (date_deadline, ip,))
        self.dbconn.commit()
        print("IP %s was added until %s" % (ip, date_deadline))
        CliLogger.write("command whitelist executed by %s for %s" % (getpass.getuser(), ip))
    
    def showAllWhitelist(self):
        """ show all whitlisted ip addresses (from config and database) """
        wl_conf = config.get("global", "whitelist")
        wl_conf = re.split("\s{1,}", wl_conf)
        
        print("Config whitelist: ", end="")
        if len(wl_conf) > 0:
            print("")
            for ip in wl_conf:
                print("  %s" % ip)
        else:
            print("  \033[33mNone\033[0m")

        res_wl = self.dbcursor.execute("SELECT DISTINCT ip, date FROM whitelist").fetchall()

        print("Database whitelist: ", end="")
        if len(res_wl) > 0:
            print("")
            for row in res_wl:
                print("  %s (expires %s)" % (row[0], row[1]))
        else:
            print("  \033[33mNone\033[0m")
    
    def showBlocked(self):
        print("Blocked by breachblocker: ", end="")
        res_bl = self.dbcursor.execute("SELECT ip, reason FROM addresses ORDER BY ip ASC").fetchall()
        if len(res_bl) == 0:
            print("\033[33mNone.\033[0m")
            return
        print("")
        for row in res_bl:
            print("  %s (%s)" % (row[0], row[1]))
    
    def checkForHost(self, host):
        ip = self._getHostAddress(host)
        if host != ip:
            print("Looking for %s (%s)..." % (host, ip))
        else:
            print("Looking for %s..." % ip)

        qry_wl = self.dbcursor.execute("SELECT COUNT(ip) FROM whitelist WHERE ip=?", (ip,))
        res_wl = qry_wl.fetchall()

        qry_bl = self.dbcursor.execute("SELECT COUNT(ip) FROM addresses WHERE ip=?", (ip,))
        res_bl = qry_bl.fetchall()

        print("Database whitelist:")
        if res_wl[0][0] == 0:
            print("  \033[33mIP %s not found\033[0m" % ip)
        else:
            print("  \033[32mIP %s found\033[0m" % ip)
        
        print("Database blocklist:")
        if res_bl[0][0] == 0:
            print("  \033[33mIP %s not found\033[0m" % ip)
        else:
            print("  \033[32mIP %s found\033[0m" % ip)
        
        print("Firewall:")
        if Firewall().check(ip):
            print("  \033[32mIP %s found\033[0m" % ip)
        else:
            print("  \033[33mIP %s not found\033[0m" % ip)
    
    def showHistory(self):
        print("Block history: ", end="")
        res = self.dbcursor.execute(
            "SELECT ip, date FROM history ORDER BY ip ASC"
        ).fetchall()
        if len(res) == 0:
            print("\033[33mNone.\033[0m")
            return
        print("")
        for row in res:
            print("  {ip} (date)".format(ip=row[0], date=row[1]))


class CliLogger(object):
    """ Logger class for cli commands """

    @staticmethod
    def write(text):
        """ writes the given text to syslog """
        syslog.openlog(str("Breachblocker-CLI"))
        syslog.syslog(syslog.LOG_NOTICE, text)


"""---------------------------
launch
---------------------------"""

if __name__ == '__main__':
    args = parser.parse_args()

    if args.no_dryrun:
        dry_run = False

    if dry_run:
        print("\033[36mRunning in DRY-RUN. No changes will be done.\033[0m")

    try:

        BreachBlocker.initDB()
        
        if args.kill:
            BBCli().flush()
            BreachBlocker().kill()
            sys.exit(0)
        elif args.remove:
            BBCli().remove(args.remove)
        elif args.wl:
            BBCli().showAllWhitelist()
        elif args.bl:
            BBCli().showBlocked()
        elif args.check:
            BBCli().checkForHost(args.check)
        elif args.whitelist:
            BBCli().wlist(args.whitelist[0], args.whitelist[1])
        elif args.flush:
            BBCli().flush()
        elif args.history:
            BBCli().showHistory()
        
        elif (args.daemon or daemon) and not args.single:
            if os.path.isfile(pid_file):
                BreachBlocker().printError("PID file exists. Is there already a process running?")
            
            pid = os.fork()
            if pid > 0:
                fh = open(pid_file, "w")
                fh.write(str(pid))
                fh.close()
                sys.exit()
            
            print("Daemon started...")
            
            sys.stdout = open(os.devnull, "a")
            if write_syslog:
                syslog.openlog(str("Breachblocker"))
                syslog.syslog(syslog.LOG_NOTICE, "Starting scan for violations (daemon mode)...")
            
            while True:
                try:
                    script = BreachBlocker()
                    script.run()
                    del script
                    time.sleep(scan_interval)
                except Exception as e:
                    syslog.syslog(syslog.LOG_NOTICE, "Exception captured: %s. Continue..." % str(e))
        
        else:
            if write_syslog:
                syslog.openlog(str("Breachblocker"))
                syslog.syslog(syslog.LOG_NOTICE, "Starting scan for violations...")
            BreachBlocker().run()
    
    except KeyboardInterrupt:
        print("User cancelled script.")
        sys.exit(1)
    
    except FileNotFoundError as e:
        print(str(e))
        sys.exit(1)
    
    except Exception as e:
        traceback.print_exc()
        try:
            os.unlink(config.get("global", "pid_file"))
        except OSError:
            pass
    
sys.exit(0)

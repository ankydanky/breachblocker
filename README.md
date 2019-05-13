# BreachBlocker
Breachblocker is a log scanner for intrusion attempts and ip blocker, similar to Fail2Ban. I created Breachblocker because 
Fail2Ban was to complicated to setup correctly in my opinion.

It can be used with following OSes:
* CentOS 7
* FreeBSD 10
* FreeBSD 11
* FreeBSD 12

and following firewalls:

* IPTABLES
* FirewallD
* IPFW

**Current version: 2.3.3**

**You need at least Python 3.5 to run the script. Python <3.5 is not supported. If you need Python 2 support please use the 2.2 branch.**

The startup-scripts folder contains SystemD and BSD Init scripts so that it can be started at boot time. It can 
run once (script) or as background-process (daemon)

Starting with 2.1.0, the tool has a cli interface to interact with. Simply use --help as paramter to see the available actions.

It can scan separate log files for different servers. Here a list of supported servers:

CentOS:
    Apache, Dovecot, UW-IMAPd, OopenSSH, Postfix, ProFTPd, Pure-FTPd, vsFTPd

FreeBSD:
    Apache, Dovecot, OpenSSH, Postfix, ProFTPd

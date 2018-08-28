# BreachBlocker
Breachblocker is a log scanner for intrusion attempts and ip blocker, similar to Fail2Ban. I created Breachblocker because 
Fail2Ban was to complicated to setup correctly in my opinion.

It can be used with CentOS 7+ and FreeBSD 10+ (IPTABLES / FirewallD / IPFW)

The startup-scripts folder contains SystemD and BSD Init scripts so that it can be started at boot time. It can 
run once (script) or as background-process (daemon)

Starting with 2.1.0, the tool has a cli interface to interact with. Simply use --help as paramter to see the available actions.

It can scan separate log files for different servers. Here a list of supported servers:

CentOS:
    Apache, Dovecot, UW-IMAPd, OopenSSH, Postfix, ProFTPd, Pure-FTPd, vsFTPd

FreeBSD:
    Apache, Dovecot, OpenSSH, Postfix, ProFTPd

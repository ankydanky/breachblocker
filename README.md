# BreachBlocker
Breachblocker is a log scanner for intrusion attempts and ip blocker, similar to Fail2Ban. I created Breachblocker because 
Fail2Ban was to complicated to setup correctly in my opinion.

It can be used with RHEL/CentOS 7+ and FreeBSD 10+ (IPTABLES / FirewallD / IPFW)

The startup-scripts folder contains SystemD and BSD Init scripts so that it can be started at boot time. It can 
run once (script) or as background-process (daemon)

HOW TO INSTALL STARTUP SCRIPTS
===============================

you MUST set daemon=True in the breachblocker.py file, otherwise
it will not work as background process



### On SystemD: ###

- copy breachblocker.service file to /etc/systemd/system
- update paths in service file
- execute:
	# systemctl daemon-reload
- execute:
	# systemctl enable breachblocker
- to test if script is working start it:
	# systemctl start breachblocker
- see if it is running:
	# systemctl status breachblocker



### On FreeBSD: ###

- copy the breachblocker file to /usr/local/rc.d
- update paths in file
- make script executable
	# chmod 755 /usr/local/etc/rc.d/breachblocker
- enable at boot:
	# sysrc breachblocker_enable=“YES”
- to test run:
	# service breachblocker start
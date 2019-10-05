## 2.5.0

* added: config option "scan_interval" in deamon mode
* added: default values if config parameter is not found
* added: cli command to view history
* changed: move object config to global config paramters

## 2.4.0

* changed: some minor config / parameter descriptions
* added: blacklist and whitelist ip addresses can be defined in a file
* added: support for netmasks in black-/whitelist

## 2.3.4:

* added: block history clearing timeout

## 2.3.3:

* fixed: restart bug in freebsd rc script
* changed: do not remove history when stopping

## 2.3.2:

* fixed: bug while removing reoccuring addresses

## 2.3.1:

* fixed: bug when removing ip addresses

## 2.3.0:

* removed: support for python 2
* added: block history \
(keep hosts which were already blocked longer: min 24 hrs on 2nd block, 48 hrs 3rd block etc)
* added: mail smtp host config

## 2.2.0:

* added FreeBSD 12 support

## 2.1.0:

* added: usage of argparse modul for parsing cli params
* added: several cli command
* added: temporary whitelist for removed ip addresses
* removed: support for python 2.6
* changed: major code changes
* added: support for python 3

## 2.0.5:

* fixed: problem with pure-ftpd server

## 2.0.4:

* fixed: dovecot "user=<>" was counted as attack

## 2.0.3:
* added: lower log timeout to block timeout if latter is lower

## 2.0.2:
* fixed: accidentally left print statement in code

## 2.0.1:
* fixed: out of range excepption in function
* added: --single parameter, run once even if daemon mode is set

## 2.0.0:
* changed: code restructuring/changing
* changed: config file using configparser
* changed: rules turned from py files to config
* fixed: memory leak when runing for weeks
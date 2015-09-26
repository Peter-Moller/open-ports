open-ports
==========

A bash-script for OS X and Linux detailing the open network connections to and from a computer

More details about the script can be found here:
http://cs.lth.se/peter-moller/script/open-portssh-en/

-----

Birds eye view of how the script works:
---------------------------------------
  * When run as root, data is generated and stored on disk
  * When run as any other user, data is presented from those files
  * Optionally, GeoLookup is done from http://api.db-ip.com (requires a free key)  
    Result from that is stored on disk to speed up future lookups
  * The external address is checked with http://ipecho.net
  * IP address (as well as default interface) is checked against `www.lu.se`

Other features:
---------------
  * The external IP-address is checked every hour to see if it has been changed
  * The age of the data files are checked: if they are older than 1 hour, a warnng is printed
  * Once every week the script looks for a new version of itself and notifies the user accordingly
  * Every two hours the checksum of the “lsof” binary is checked to look for intrusions: if it has been changed a warning is printed instead of output
  * On OS X only:
    * lists all interfaces, in priority order
    * looks for available software updates every 6 hours
  * When the script has been installed, or updated, a “signal” is send to me (a curl to a specific URL that I check for in the apache-log on the dept. server. This is done mostly out of curiosity and no information is used in any other way)


Operation of the script, in line-order:
----------------------------------------------------
 1. Quit if either:
    - `open_ports.sh` is running with the same `UID`
    - the OS is not either Darwin or Linux
 2. Functions
 3. Definitions of variables (I'm unsure if they “should” come before the functions, but I'm pretty sure it doesn't matter… :-)
 4. If script is run by `root`, generate data and then exit
 5. Checks:
     - is there an update?
     - is there a STOP-flag (`lsof` has been changed)? If so, notify user and exit the script
     - Is there any data file at all? Warn and exit if not
     - If OS X: check to see if the `launchd`-part is running. Warn if not
     - Are the data files older than 1 hour? Warn if so
     - Do we have an IP address (rather: do we have a default interface. Check is performed against `www.lu.se`)? Warn otherwise
 6. Find out, and print system information
 7. If OS X: look for software updates (this is done every 6 houres; result stored in `/tmp/swu.temp`)
 8. Print the head
 9. Print the ESTABLISHED files (IPv4 first, IPv6 next)
 10. Print the LISTEN files


When the script has been modified, I (manually) move it to the deployment-server, OpenPortsURL 
(http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts), and create a `sha1`-file so that clients may 
get information about a new version being released.

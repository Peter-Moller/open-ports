open-ports
==========

A bash-script for OS X and Linux detailing the open network connections to and from a computer

More information about the script can be found here:
http://cs.lth.se/peter-moller/script/open-portssh-en/

-----

Birds eye view of how the script works:
---------------------------------------
  * When run as root, data is generated and stored on disk
  * When run as any other user, data is presented from those files
  * Optionally, GeoLookup is done from http://api.db-ip.com (requires a free key)  
    Result from that is stored on disk to speed up future lookups
  * The external address is checked with http://ipecho.net
  * IP address (as well as default interface, checked against `www.lu.se`)

*One clarification: the script **needs** to run as root, or you will only see your own connections and that makes it much less valuable!*

Other features:
---------------
  * The external IP-address is checked every hour to see if it has been changed
  * The age of the data files are checked: if they are older than 1 hour, a warnng is printed
  * Once every week the script looks for a new version of itself and notifies the user accordingly
  * Every two hours the checksum of the “lsof” binary is checked to look for intrusions: if it has been changed a warning is printed instead of output
  * On OS X only:
    * lists all interfaces, in priority order
    * looks for available software updates every 6 hours
  * When the script has been installed, or updated, a “signal” is send to me (a curl to a specific URL that I check for in the apache-log on the dept. server. This is done out of curiosity of how many installs and updates there are, and no information is used in any other way)

Tha basic functionality of the script can be encapsulated in:  
ESTABLISHED connections (Darwin, `IPv4`; replace the `4` with a `6` for `IPv6`):  
`lsof +c 0 -i 4 -n | grep EST | sort -f -k 1,1 | cut -d\( -f1 | awk '{ print $1" "$3" "$9 }' | sed 's/\ [[:digit:]].*-\>/\ /g' | sed 's/:/\ /g' | sort -f | uniq -c`  
and  
LISTEN connections (Darwin, same as above, almost...):  
`lsof +c 0 -i 4 -n | grep LISTEN | sort -f -k 1,1 | cut -d\( -f1 | awk '{ print "4 - "$1" "$3" "$9 }' | sed 's/:/\ /g' | sed 's/\ [[:digit:]]\{2,5\}$/\ anonymous_port/g' | uniq`  
For Linux the central lines are almost the same.


Operation of the script, in line-order:
----------------------------------------------------
 1. Quit if either:
    - `open_ports.sh` is already running with the same `$UID`
    - the OS is not Darwin or Linux
 2. Functions
 3. Definitions of variables (I'm unsure if they “should” come before the functions, but I'm pretty sure it doesn't matter… :-)
 4. If script is run by `root`, generate data and then exit
 5. Checks:
     - is there an update?
     - is there a STOP-flag (`lsof` has been changed)? If so, notify user and exit the script
     - Is there any data file at all? Warn and exit if not
     - If OS X: check to see if the `launchd`-part is running. Warn if not
     - Are the data files older than 1 hour? Warn if so
     - Do we have an IP address (rather: do we have a default interface – checked against `www.lu.se`)? Warn otherwise
 6. Find out, and print system information
 7. If OS X: look for software updates (this is done every 6 houres; result stored in `/tmp/swu.temp`)
 8. Print the head
 9. Print the ESTABLISHED files (IPv4 first, IPv6 next)
 10. Print the LISTEN files


When the script has been modified, I (manually) move it to the deployment-server, OpenPortsURL 
(http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts), and create a `sha1`-file so that clients may 
get information about a new version being released.

#!/bin/bash
# Script to install open_ports.sh on Linux
# © Peter Möller, 2011-2012
# open_ports.sh home page (english):
# http://cs.lth.se/kontakt/peter_moller/script/open_portssh_en
# open_ports.sh home page (swedish):
# http://cs.lth.se/kontakt/peter_moller/script/open_portssh
#
# 2011-03-10 / Peter Möller, Datavetenskap, LTH
# 2011-11-17: Fixed a bug that wiped out a previous crontab
# 2011-11-30: Small fix
# 2015-09-16: Moved to GitHub
# Location: 
# http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts/open_ports_install_linux.sh


# Find out what OS is running. Quit if not Mac OS X or Linux
OS="$(uname -s)"
if [ ! "$OS" = "Darwin" -a ! "$OS" = "Linux" ]; then
  echo "Unknown Operating System!!! (according to \"uname -s\")"
  echo "This script only works on Mac OS X or Linux."
  echo "Exiting..."
  exit 1
fi

# Make sure the user is "root"
if [ ! "$USER" = "root" ] ; then
  echo "Must be run by root!"
  echo "Exiting..."
  exit 1
fi

# Inform the user of what is going to happen
printf "\e[1;4mInstallation of open_ports.sh:\e[0m\n"
echo "This will install \"open_ports.sh\" on your computer."
echo
echo "The home page for the project is located here:"
echo "http://cs.lth.se/kontakt/peter_moller/script/open_portssh_en"
echo "There you will find more information about the script and also how to remove it."
echo
echo "Now the script will be downloaded and installed:"

# Check to see if "curl" exists
if [ -z "$(which -a curl 2>/dev/null)" ]; then
  echo "Warning: \"curl\" not found! Update of script will not work!"
fi

# make sure openssl exists
if [ -z $(which openssl) ]; then
  echo "Warning: \"openssl\" not found! Checksum-verification will not work!"
fi

# BINDIR points to the "binary"
BINDIR="/usr/bin"
# PREFIX points to where all the datafiles are stored
PREFIX="/usr/share/cs.lth.se/OpenPorts"
# IP_CACHE is a growing list of IP-addresses and their geo location. 
# Since this is being used by other scripts, it's not in the OpenPorts directory
IP_CACHE="/usr/share/cs.lth.se/ip_cache.txt"
# GeoLookupDir is a dir where the geo lookup is stored
GeoLookupDir="/usr/share/cs.lth.se/GeoLookup"
# EXTERN stores the computers "external" address. Checked hourly
EXTERN="$PREFIX/ExternIP.txt"
# FILE4 stores current IPv4-ESTABLISHED connections. Generated every two minutes!
FILE4="$PREFIX/ip4.txt"
# FILE6 stores current IPv6-ESTABLISHED connections. Generated every two minutes!
FILE6="$PREFIX/ip6.txt"
# FILE_LISTEN stores current LISTEN connections. Generated every two minutes!
FILE_LISTEN="$PREFIX/listen.txt"
# CHECKSUM stores a sha1-checksum for the lsof-binary. Cheched every two houres
CHECKSUM="$PREFIX/Checksum.txt"
# IP_LOCATE_CACHE is a temporary file that stores the geo location of the computers external address
IP_LOCATE_CACHE="$PREFIX"/ip_locate_cache.txt
# OP_LOGG is a log file where all things related to open_ports.sh (install and upgrades) are noted
OP_LOGG="$PREFIX"/OpenPorts_log.txt



# fetch the open_ports-script
printf "1. Fetching the main script (installs in \"$BINDIR\")..."
#curl -o $BINDIR/open_ports.sh http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts/open_ports.sh 2>/dev/null
curl -o /tmp/open_ports.sh http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts/open_ports.sh 2>/dev/null
curl -o /tmp/open_ports.sh.sha1 http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts/open_ports.sh.sha1 2>/dev/null
if [ "$(openssl sha1 /tmp/${ScriptName} | awk '{ print $2 }')" = "$(less /tmp/${ScriptName}.sha1)" ]; then
  mv /tmp/open_ports.sh /usr/bin/open_ports.sh
  chmod 755 $BINDIR/open_ports.sh
else
  echo "Checksum does NOT match!! Installation aborted!"
  exit 1
fi

# Countries.txt
curl -o /tmp/Countries.txt http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts/Countries.txt 2>/dev/null
curl -o /tmp/Countries.txt.sha1 http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts/Countries.txt.sha1 2>/dev/null
if [ "$(openssl sha1 /tmp/Countries.txt | awk '{ print $2 }')" = "$(less /tmp/Countries.txt.sha1)" ]; then
  mv /tmp/Countries.txt ${PREFIX}/Countries.txt
  rm /tmp/Countries.txt.sha1 2>/dev/null
fi
printf " done!\n"

# Fix cron
printf "2. Fixing crontab for root (crontab runs the script every two minutes.\n"
printf "   This will NOT mess up previous crontab entries)..."
crontab -l | grep -v "open_ports.sh" > /tmp/CRONFILE
echo "*/2 * * * * $BINDIR/open_ports.sh" >> /tmp/CRONFILE
crontab < /tmp/CRONFILE
rm /tmp/CRONFILE
printf " done!\n"


# Create the directory for the files and set the access rights
printf "3. Creating the data-directories (located in \"$PREFIX\")..."
mkdir -p "$PREFIX"
chmod 755 "$PREFIX"
mkdir "$GeoLookupDir"
chmod 777 "$GeoLookupDir"
#touch "$FILE4" "$FILE6" "$IP_CACHE" "$IP_LOCATE_CACHE"
#chmod 666 "$FILE4" "$FILE6" "$IP_CACHE" "$IP_LOCATE_CACHE"
touch "$FILE4" "$FILE6"
chmod 666 "$FILE4" "$FILE6"
printf " done!\n"

echo 
printf "\e[1;4mDone!\e[0m\n"
echo "\"open_ports.sh\" is now running and collect information every two minutes."
echo "Run the script as an ordinary user to see the data."
echo
echo "In order for the geographical lookup to work, you need to get a [free] key from \"http://db-ip.com/api/\"."
echo "Once you've gotten that key in your email, you need to store it as \"apidb.key\" in \"$PREFIX\""
echo "Opening this address in a few seconds..."
/bin/sleep 5
open "http://db-ip.com/api/free" &
echo
echo "Please do not forget to upgrade the script once every month or so! (\"open_ports.sh -u\")"
echo "Also, please feel free to report bugs and email suggestions for improvements!"
echo "Thank you!"
echo "Peter Möller, Department of Computer Science, Lund University, Lund, Sweden"

# Make an entry into the log book
echo "$(date): \"open_ports.sh\" installed" >> "$OP_LOGG"

exit 0

#!/bin/bash
# Script to install open_ports.sh
# © Peter Möller, 2011-2012
# 2011-05-05 / Peter Möller, Datavetenskap, LTH
# 2011-11-17: Fixed check of OS X version to determine which GeekTool to use
# 2011-12-06: Added printout during installation
# 2014-03-02: Changed to accomodated 
# 2015-09-16: Moved to GitHub
# Location: 
# http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts/open_ports_install.sh


# Make sure the user is "root"
if [ ! "$USER" = "root" ] ; then
  echo "Must be run by root!"
  echo "Exiting..."
  exit 1
fi

# ScriptName is the name of the script
ScriptName="open_ports.sh"

# Determine what OS is running and warn if not 10.6 or 10.7:
SW_VERS="$(sw_vers -productVersion | cut -d\. -f2)"
if [ -z "$(echo "6789" | grep -o $SW_VERS)" ]; then
  echo "\"$ScriptName\" has not been tried with Mac OS X 10.$SW_VERS!!"
  echo "It may not work."
fi


# BINDIR points to the "binary"
BINDIR="/usr/local/bin"
# PREFIX points to where all the datafiles are stored
PREFIX="/Library/cs.lth.se/OpenPorts"
## IP_CACHE is a growing list of IP-addresses and their geo location. 
## Since this is being used by other scripts, it's not in the OpenPorts directory
#IP_CACHE="/Library/cs.lth.se/ip_cache.txt"
# GeoLookupDir is a dir where the geo lookup is stored
GeoLookupDir="/Library/cs.lth.se/GeoLookup"
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
## IP_LOCATE_CACHE is a temporary file that stores the geo location of the computers external address
#IP_LOCATE_CACHE="$PREFIX"/ip_locate_cache.txt
# OP_LOGG is a log file where all things related to open_ports.sh (install and upgrades) are noted
OP_LOGG="$PREFIX"/OpenPorts_log.txt

# Inform the user of what is going to happen
printf "\e[1;4mInstallation of \"$ScriptName\":\e[0m\n"
echo "This will install \"$ScriptName\" on your computer."
echo
echo "The home page for the project is located here:"
echo "http://cs.lth.se/kontakt/peter_moller/script/open_portssh_en"
echo "There you will find more information about the script and also how to remove it."
echo
echo "Now the script will be downloaded and installed:"

# Fetch and launch the launchd-component
printf "1. Fetching the launchd-component (runs the script every two minutes)..."
curl -o /Library/LaunchDaemons/se.lth.cs.open_ports.plist http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts/se.lth.cs.open_ports.plist 2>/dev/null
chmod 644 /Library/LaunchDaemons/se.lth.cs.open_ports.plist
launchctl load /Library/LaunchDaemons/se.lth.cs.open_ports.plist
launchctl start se.lth.cs.open_ports
printf " done!\n"

# Fetch the script
printf "2. Fetching the main script and the country list..."
# open_ports.sh
curl -o /tmp/${ScriptName} http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts/${ScriptName} 2>/dev/null
curl -o /tmp/${ScriptName}.sha1 http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts/${ScriptName}.sha1 2>/dev/null
if [ "$(openssl sha1 /tmp/${ScriptName} | awk '{ print $2 }')" = "$(less /tmp/${ScriptName}.sha1)" ]; then
  mkdir -p /usr/local/bin 2>/dev/null
  mv /tmp/${ScriptName} ${BINDIR}/${ScriptName}
  chmod 755 ${BINDIR}/${ScriptName}
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

# Create the directory for the files and set the access rights
printf "3. Creating the data-directories..."
mkdir -p "$PREFIX"
chmod 755 "$PREFIX"
mkdir "$GeoLookupDir"
chmod 777 "$GeoLookupDir"
touch "$FILE4" "$FILE6"
chmod 666 "$FILE4" "$FILE6"
printf " done!\n"

# Send a signal that someone has installed the script
# This is only to give me feedback that someone is actually using this
# I will *not* use the data in any way or give it away!
curl -s -f -e "$ScriptName OS X 10.${SW_VERS}" -o /dev/null http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts/installed 2>/dev/null

echo "Done installing base parts of \"$ScriptName\". Now proceeding to install GeekTool"
echo "(GeekTool is not a part of \"$ScriptName\"; it is used to display the output of the script"
echo "on the desktop of your computer. You may skip it if you like)."
echo

# Getting GeekTool
if [ -z "$(ls /Library/PreferencePanes/GeekTool.prefPane 2>/dev/null)" -a -z "$(ls /Users/*/Library/PreferencePanes/GeekTool.prefPane 2>/dev/null)" -a -z "$(ls /Applications/GeekTool.app 2>/dev/null)" ]; then
  if [ "$SW_VERS" = "6" ]; then
    echo "Fetching GeekTool for Snow Leopard"
    # Get GeekTook
    curl -o /tmp/GeekTool.dmg http://update.tynsoe.org/geektool3/Public/GeekTool%203.0.dmg 2>/dev/null
    hdiutil mount /tmp/GeekTool.dmg
    open /Volumes/GeekTool\ 3/
    echo "GeekTool has been downloaded, but you must install it yourself!"
  elif [ "$SW_VERS" = "7" -o "$SW_VERS" = "8" -o "$SW_VERS" = "9" -o "$SW_VERS" = "10" -o "$SW_VERS" = "11" ]; then
    echo "GeekTool is available from this address:"
    echo "http://projects.tynsoe.org/en/geektool/download.php"
    echo "Opening this address in a few seconds..."
    /bin/sleep 5
    open "http://projects.tynsoe.org/en/geektool/download.php" &
  else
    echo "Sorry: you are running a version of Mac OS X that will not work with GeekTool."
    echo "You will have to find a version for yourself..."
  fi
else
  echo "It looks as if you already have GeekTool installed."
fi

echo 
printf "\e[1;4mDone!\e[0m\n"
echo "\"$ScriptName\" is now running and collect information every two minutes."
echo "Run the script as an ordinary user to see the data."
echo
printf "\e[1;3mLocations:\e[0m\n"
echo "The script is located in \"${BINDIR}\""
echo "The data files are stored in \"$PREFIX\""
echo "The launchd-file is \"/Library/LaunchDaemons/se.lth.cs.open_ports.plist\""
echo "These are the files you need to remove to uninstall!"
echo
echo "In order for the geographical lookup to work, you need to get a [free] key from \"http://db-ip.com/api/\"."
echo "Once you've gotten that key in your email, you need to store it as \"apidb.key\" in \"$PREFIX\""
echo "Opening this address in a few seconds..."
/bin/sleep 5
open "http://db-ip.com/api/free" &
echo
echo "Please do not forget to upgrade the script once every month or so! (\"$ScriptName -u\")"
echo "(I would suggest that you do this from \"root\"_s crontab)"
echo
echo "Also, please feel free to report bugs and email suggestions for improvements!"
echo "Thank you!"
echo "Peter Möller, Department of Computer Science, Lund University, Lund, Sweden"

# Make an entry into the log book
echo "$(date): \"open_ports.sh\" installed" >> "$OP_LOGG"
exit 0

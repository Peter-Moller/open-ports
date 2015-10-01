#!/bin/bash
#
# Script to list open TCP-connections on Mac OS X 10.6, 10.7, 10.8, 10.9, 10.10 and 10.11 and Linux
# The script came to life in 2011
# 
# Copyright 2015 Peter Möller, Dept of Copmuter Science, Lund University
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# 
# Script home page (english):
# http://cs.lth.se/kontakt/peter_moller/script/open_portssh_en
# Script home page (swedish):
# http://cs.lth.se/kontakt/peter_moller/script/open_portssh
# 2011-06-23  All comments translated to english (phew!)
# 2011-07-13  Auto-update disabled! Instead, it notify the user of updates
#             Also feedback for when data is generated
#             Bug-fix from Roman Weber about IPv6-parsing (thanks!)
# 2011-08-27  Changed URL of "whatismyip"
# 2011-11-30  Polished
# 2011-12-07  Version included in curl call
# 2013-03-11  Disabled  the use of geoiptool (sadly). Looking for a replacement
#             Also changed the external IP-address lookup
# 2013-04-23  Fixed garbage in the $IP_CACHE-file
# 2014-03-01  Implemented a new IP-lookup system using http://db-ip.com/ (Thank you, guys!)
# 2015-09-16  Moved to GitHub (finally!)
#
# Version:
VER="2.6.2"
#
# Note: The script is dependant on two external web-addresses:
# 1. http://api.db-ip.com/addrinfo?addr=8.9.10.11&api_key=123456789123456789
#    Performs the mapping from IP address to Country and City
#    One must register by them and get a key (stored in $PREFIX/apidb.key)
#    Also, one must not perform more than 5.000 lookups per day
# 2. http://tejji.com/ip/my-ip-address.aspx
#    Finds out the external IP-address you have  if you are behind a NAT-router
#
# Adaption to Linux (Mandriva)
# Lines that start with "##" are “issues” from Mac OS X to Linux
#
# Things to fix:
# • How to present it on the screen on Linux
# • IPv6/ESTABLISHED!

help() {
  echo
  echo "Usage: $0 [-u]"
  echo
  echo "-u: Update the script"
  echo
  echo "If run by root: datafiles in /Library/cs.lth.se/OpenPorts (Mac) or /usr/share/cs.lth.se/OpenPorts (Linux) are created, but no output."
  echo "If run by any other user: output is displayed based on those datafiles."
  echo
  echo "This script is supposed to be used in conjunction with a launchd-component, se.lth.cs.open_ports,"
  echo "that creates the datafiles in /Library/OpenPorts every two minutes. The use of GeekTool to display the result"
  echo "is also part of the idea behind this script!"
  exit 0
}

# Locate an IP-address. Gives:
# Country: Country
# City: City
# to std. out
# 2014-03-01: OBSOLETE!! Only here for reference
locate_ip() {
  curl http://www.geoiptool.com/en/?IP=$1 2>/dev/null | awk '
  /<td.*>(Country:|City)/ {
  record="t";gsub("[\t ]*<[^>]*>",""); printf("%-1s ",$0);next;
  }
  record == "t" { gsub("[\t ]*<[^>]*>[\t ]*","");print $0;record="f";next}
  {next}
  END{print ""}'
}


# Do the Geo Lookup (if key exists)
# Assumes:
# - $1: IP
# curl 'http://api.db-ip.com/addrinfo?addr=68.169.130.16&api_key=123456789123456789'
# Gives:
# - a file, $GeoLookupDir/$IP_to_check, containing "Country Name:City Name"
function PerformGeoLookup ()
{
  if [ -n "$GeoLookupKey" ]; then
    IP_to_check="$1"
    if [ -z "$(echo $IP_to_check | sed 's/[0-9\.]//g')" ]; then
      Rad="$(curl -s "$GeoLookupURL$IP_to_check&api_key=$GeoLookupKey")"
      [ "$debug" = "t" ] && echo "$(date +%F" "%T); #99; $$; User=\"$USER\"; PerformGeoLookup, IP_to_check=\"$IP_to_check\", Rad=\"$Rad\"" >> $IP_loggfile
      # -> Rad='{"address":"78.69.30.61","country":"SE","stateprov":"Stockholm County","city":"Farsta"}'
      # Simple sanity check: count the number of qoutation marks (should be 16)
      if [ "$(echo $Rad | grep -o '"' | wc -w | awk '{print $1}')" -eq 16 ]; then
        City="$(echo $Rad | cut -d\" -f 16)"
        Country="$(grep "$(echo $Rad | cut -d\" -f 8)" $CountryList | cut -d: -f2)"
      else
        City="look up"
        Country="Could not"
      fi
      # Write to file
      echo "$City:$Country" > "$GeoLookupDir/${IP_to_check}.txt"
      [ "$debug" = "t" ] && echo "$(date +%F" "%T); #95; $$; User=\"$USER\"; PerformGeoLookup (IP=\"$IP\", IP_to_check=\"$IP_to_check\", City=\"$City\", Country=\"$Country\")" >> $IP_loggfile
    else
      City="look up"
      Country="Could not"
    fi
  fi
}


# Check to see if $IP already exist in $GeoLookupDir and get $Country and $City
# Otherwise, find the information and update $IP_CACHE
# Assume:
# - IP
# Gives: $Country & $City and eventually a new entry in $GeoLookupDir
function GetCityCountry()
{
  # (DIRT REMOVED) DIRTY fix for IPv6. Will need to work on this!!
  #if [ -n "$(echo $IP | sed 's/[0-9.]//g')" ]; then
  #  IP="$(echo $IP | cut -d: -f1)"
  #fi
  if [ -r "$GeoLookupDir/${IP}.txt" ]; then
    City="$(less "$GeoLookupDir/${IP}.txt" | cut -d: -f1 | native2ascii -encoding UTF-8 -reverse)"
    Country="$(less "$GeoLookupDir/${IP}.txt" | cut -d: -f2)"
    # FUTURE FEATURE: INCREASE COUNTER
    [ "$debug" = "t" ] && echo "$(date +%F" "%T); #135; $$; User=\"$USER\"; GetCityCountry ($IP, City=\"$City\", Country=\"$Country\")" >> $IP_loggfile
  else
    PerformGeoLookup $IP
  fi
}

# Get DNS for $IP
# Gives: $HOSTNAME
# Will also deal with the private addresses:
# • 10.x.x.x
# • 172.16.x.x
# • 192.168.x.x
# as well as self-assigned address:
# 169.254.x.x
function GetDNS()
{
  PrivateAddress="No"
  if [ -z "${IP/127.0.0.1}" ]; then
    HOSTNAME="localhost"
  elif [ "$(echo "$IP" | cut -d\. -f1)" = "10" ]; then
    HOSTNAME="Private address ($IP)"
    PrivateAddress="Yes"
  elif [ "$(echo "$IP" | cut -d\. -f1,2)" = "172.16" ]; then
    HOSTNAME="Private address ($IP)"
    PrivateAddress="Yes"
  elif [ "$(echo "$IP" | cut -d\. -f1,2)" = "192.168" ]; then
    HOSTNAME="Private address ($IP)"
    PrivateAddress="Yes"
  elif [ "$(echo "$IP" | cut -d\. -f1,2)" = "169.254" ]; then
    HOSTNAME="Self-assigned address ($IP)"
    PrivateAddress="Yes"
  else
    HOSTNAME_tmp="$(host -W 2 $IP)"
    ERR="$?"
    if [ ! "$ERR" = "0" ]; then
      HOSTNAME="$IP could not be looked up! (DNS timeout)"
    else
      HOSTNAME=`echo $HOSTNAME_tmp | awk '{ print $NF }' | sed 's/\.$//g'`
    fi
  fi
}


# Quit if there already is a running “open_ports.sh”
# Typical line:
#   501  7307  7301   0  9:53am ttys001    0:00.02 /bin/bash /usr/bin/open_ports.sh
if [ "$(ps -ef | grep "^\ *${UID}\ .*/[b]ash\ .*/[o]pen_ports.sh$" | wc -l)" -gt "2" ]; then
  echo "\"open_ports.sh\" already running -- will exit now"
  exit 0
fi

# Find the OS. Quit if it's not either Mac OS X or Linux
OS="$(uname -s)"
if [ ! "$OS" = "Darwin" -a ! "$OS" = "Linux" ]; then
  echo "Unknown Operating System!!!"
  echo "This script only works on Mac OS X or Linux."
  echo "Exiting..."
  exit 1
fi

# Read the parameters:
while getopts ":hud" opt; do
case $opt in
    u ) fetch_new=t;;
    d ) debug=t;;
 \?|h ) help;;
esac
done


# Check for update
# We come here when the script is older than 7 days 
# or
# from the function “UpdateScript”
# 
# If no new update is available, the script is touched (to postpone any new check for a week)
CheckForUpdate() {
  NewScriptAvailable=f
  # First, download the script from the server
  curl -s -f -e "$ScriptName ver:$VER" -o /tmp/"$ScriptName" "$OpenPortsURL"/"$ScriptName" 2>/dev/null
  curl -s -f -e "$ScriptName ver:$VER" -o /tmp/"$ScriptName".sha1 "$OpenPortsURL"/"$ScriptName".sha1 2>/dev/null
  ERR=$?
  if [ "$ERR" -ne 0 ] ; then
    case "$ERR" in
      6) echo "Error: unable to resolve host";;
      7) echo "Error: unable to connect to host";;
      22) echo "Error fetching http-page (error code 4nn or 5nn)";;
    esac
    echo "The file \"$ScriptName\" could not be fetched from \"$OpenPortsURL/$ScriptName\""
    UpdateMessage="{ESC}${BlackBack};${RedFont}mCould not check for new version of \"$ScriptName\" (network error)\n\n"
    #echo "Exiting! Fix yourself..."
    #exit 1
  fi
  # Compare the checksum of the script with the fetched sha1-sum
  # If they diff, there is a new script available
  # If not, touch the script to make it not check again in 2 minutes!
  if [ "$(openssl sha1 /tmp/"$ScriptName" | awk '{ print $2 }')" = "$(less /tmp/"$ScriptName".sha1)" ]; then
    if [ -n "$(diff /tmp/$ScriptName $BINDIR/$ScriptName 2> /dev/null)" ] ; then
      NewScriptAvailable=t
      UpdateMessage="${ESC}${BlackBack};${RedFont}mUpdate to $ScriptName available! (update with: \"$ScriptName -u\" as root)${Reset}\n\n"
    else
      touch $BINDIR/$ScriptName 2>/dev/null
    fi
  else
    CheckSumError=t
    UpdateMessage="${ESC}${BlackBack};${RedFont}mUpdate check of $ScriptName: checksum-check failed!${Reset}\n\n"
  fi
  }


# Update [and quit]
# We come here on a direct request
# If there is no newer script, the present one is touched so that the next check is done in a week from now
UpdateScript() {
  CheckForUpdate
  if [ "$CheckSumError" = "t" ]; then
    echo "Checksum of the fetched \"$ScriptName\" does NOT check out. Look into this! No update performed!"
    exit 1
  fi
  if [ "$NewScriptAvailable" = "t" ]; then
    /bin/rm -f $BINDIR/"$ScriptName" 2> /dev/null
    /bin/mv /tmp/"$ScriptName" $BINDIR/"$ScriptName"
    chmod 755 $BINDIR/"$ScriptName"
    echo "A new version of \"$ScriptName\" was installed successfully!"
    echo "Script updated. Exiting"
    # Make an entry into the log book
    echo "$(date): \"open_ports.sh\" upgraded" >> "$OP_LOGG"

    # Send a signal that someone has updated the script
    # This is only to give me feedback that someone is actually using this. I will *not* use the data in any way nor give it away or sell it!
    curl -s -f -e "$ScriptName ver:$VER" -o /dev/null "$OpenPortsURL"/updated 2>/dev/null
    
    # Also, fix moving the script to /usr/local/bin
    if [ -n "$(grep "/usr/bin/open_ports.sh" /Library/LaunchDaemons/se.lth.cs.open_ports.plist 2>/dev/null)" ]; then
      # Edit the plist-file
      sed -e 's;/usr/bin/;/usr/local/bin/;' -i .bak /Library/LaunchDaemons/se.lth.cs.open_ports.plist
      # Stop and restart the launchd job
      /bin/launchctl unload /Library/LaunchDaemons/se.lth.cs.open_ports.plist
      /bin/launchctl load /Library/LaunchDaemons/se.lth.cs.open_ports.plist
    fi
    # Also do this on Linux
    if [ "$OS" = "Linux" ]; then
      crontab -l | grep -v "open_ports.sh" > /tmp/CRONFILE
      echo "*/2 * * * * $BINDIR/open_ports.sh" >> /tmp/CRONFILE
      crontab < /tmp/CRONFILE
    fi

    exit 0
  else
    echo "You already have the latest version of \"$ScriptName\"!"
    touch $BINDIR/$ScriptName
    exit 0
  fi
  }


# Get, and print, IP-addresses for all active interfaces based on $NetworkInterfaces
# This is, as yet, Mac-only
function PrintAllInterfaces()
{
  NSOfile="/tmp/NetworkServiceOrder_$$.txt"
  networksetup -listnetworkserviceorder  | grep -A 1 "^([0-9])\ " | grep "[a-z][0-9])$" | cut -d: -f2,3 | sed -e 's/, Device//g' -e 's/)//g' -e 's/^ //g' > $NSOfile
  NetworkInterfaces="$(less $NSOfile | cut -d: -f2)"
  # Ex: NetworkInterfaces=' en0 en1 en5 en2 bridge0'
  #echo "Available network interfaces: $NetworkInterfaces"
  FormatStringInterfaces="%-25s%-5s%-17s%-26s"
  # Thunderbolt Ethernet en1  130.235.120.242  fe80::1610:9fff:fece:fd95
  # 1234567890123456789012345678901234567890123456789012345678901234567890
  #          1         2         3         4         5         6         7

  NumActiveInterfaces="$(ifconfig | grep ":\ active$" | wc -l | awk '{print $1}')"

  # Print information about the various interfaces if there are more than one interface
  if [ $NumActiveInterfaces -gt 1 ]; then
    echo
    printf "${ESC}${BlackBack};${WhiteFont}mActive interfaces, in service order:${Reset}\n"
    IfNum=1
    for j in $NetworkInterfaces
    do
      IF="$(ifconfig $j 2>/dev/null | egrep "inet[6]?\ |status:\ ")"
      # Ex: IF='inet6 fe80::217:f2ff:fe04:4229%en1 prefixlen 64 scopeid 0x5 inet 192.168.1.69 netmask 0xffffff00 broadcast 192.168.1.255 status: active'
      if [ $? -eq 0 ]; then
        Active="$(echo $IF | egrep -o "status: [a-z0-9][^\ ]*" | awk '{print $2}')"
        if [ -z "${Active/active/}" ]; then
          IFName="$(grep $j $NSOfile | cut -d: -f1)"
          # Ex: IFName='Ethernet 2'
          I4="$IFName ($j): $(echo $IF | egrep -o "inet\ [a-z0-9][^\ ]*" | awk '{print $2}')"
           # Ex: I4='Ethernet 2 (en1): 192.168.1.69'
          I6="$IFName ($j): $(echo $IF | egrep -o "inet6\ [a-z0-9][^\ ]*" | awk '{print $2}' | egrep -o "[^%]*")"
          # Ex: I6='Ethernet 2 (en1): fe80::217:f2ff:fe04:4229'
          # Without the last part, it will be: I6='Ethernet 2 (en1): fe80::217:f2ff:fe04:4229%en1'
          printf "${ESC}${WhiteBack};${BlackFont}m${FormatStringInterfaces}${Reset}\n" "${IfNum}. ${IFName}" "$j" "$(echo $IF | egrep -o "inet\ [a-z0-9][^\ ]*" | awk '{print $2}')" "$(echo $IF | egrep -o "inet6\ [a-z0-9][^\ ]*" | awk '{print $2}' | egrep -o "[^%]*")"
          let IfNum=( $IfNum + 1 )
        fi
      fi
    done
  fi
  # Clean up the $NSOfile
  /bin/rm "$NSOfile" 2>/dev/null
}


# Basic settings:
# PREFIX points to where the data files are stored. 
# IP_CACHE is a growing list of IP-addresses  and their geographical location.
# Since this is used by other scripts, it is not located in the OpenPorts directory
if [ "$OS" = "Darwin" ]; then
  PREFIX="/Library/cs.lth.se/OpenPorts"
  IP_CACHE="/Library/cs.lth.se/ip_cache.txt"
  # GeoLookupDir is a dir where the geo lookup is stored
  GeoLookupDir="/Library/cs.lth.se/GeoLookup"
  DEFAULT_INTERFACE="$(route get www.lu.se | grep interface | awk '{ print $2 }')"
  MY_IP_ADDRESS="$(ifconfig $DEFAULT_INTERFACE | grep "inet " | awk '{ print $2 }')"
  #DOMAIN="`ipconfig getpacket en0 | grep 'domain_name (string)' | awk '{ print $3 }'`"
  DOMAIN="$(hostname | cut -d\. -f2-7)"
  MTIME60m="-mtime -60m"
  MTIME120m="-mtime -120m"
  MTIME7d="-mtime -7d"
elif [ "$OS" = "Linux" ]; then
  PREFIX="/usr/share/cs.lth.se/OpenPorts"
  IP_CACHE="/usr/share/cs.lth.se/ip_cache.txt"
  # GeoLookup is a dir where the geo lookup is stored
  GeoLookupDir="/usr/share/cs.lth.se/GeoLookup"
  DEFAULT_INTERFACE="$(/sbin/route | grep "^default" | awk '{ print $NF }')"
  MY_IP_ADDRESS="$(/sbin/ifconfig $DEFAULT_INTERFACE | grep "inet " | awk '{ print $2 }' | cut -d: -f2)"
  DOMAIN="$(dig +search +short -x $MY_IP_ADDRESS | cut -d\. -f2-8 | sed 's/\.$//g')"
  MTIME60m="-mmin -60"
  MTIME120m="-mmin +120"
  MTIME7d="-mtime -7"
fi
# BINDIR is where open_ports.sh should be
BINDIR="/usr/local/bin"
# OpenPortURL is where open_ports.sh and Countries.txt resides
OpenPortsURL="http://fileadmin.cs.lth.se/cs/Personal/Peter_Moller/scripts"
# NAT has content if we are on a private net (^192.168.|^172.16.|^10.) and empty otherwise
NAT="$(echo $MY_IP_ADDRESS | egrep "^192.168.|^172.16.|^10.")"
# ScriptName is simply the name of the script...
ScriptName="$(basename $0)"
# EXTERN stores the computers “external” address. It is checked hourly
EXTERN="$PREFIX"/ExternIP.txt
# ExternHistory stores a history of your external IP-addresses
ExternHistory="$PREFIX"/ExternIP_history.txt
# GeoLookupURL is where the Geo Lookup is performed
GeoLookupURL="http://api.db-ip.com/addrinfo?addr="
# GeoLookupKey is the key that is nessecary to actually perform geolookup
GeoLookupKey="$(cat $PREFIX/apidb.key 2>/dev/null)"
# FILE4 stores currently IPv4-ESTABLISHED connections. Generated every 2 minutes
FILE4="$PREFIX"/ip4.txt
# FILE6 stores currently IPv6-ESTABLISHED connections. Generated every 2 minutes
FILE6="$PREFIX"/ip6.txt
# FILE_LISTEN stores current LISTEN-connections. Generated every 2 minutes
FILE_LISTEN="$PREFIX"/listen.txt
# CHECKSUM stores a sha1 checksum for the lsof-binary. Checked every 2 houres
CHECKSUM="$PREFIX"/lsof_checksum.txt
# IP_LOCATE_CACHE is a temporary file that stores the geo location of the external address
IP_LOCATE_CACHE="$PREFIX"/ip_locate_cache.txt
# Empty file whose existence signals that the launchd-part of open_ports is NOT running
LAUNCHD_FLAG="$PREFIX"/no_launchd
# SoftwareUpdate-fil (temporary)
SoftUpd=/tmp/swu.temp
# String for printf (used to print ESTABLISHED-connections)
Formatstring1="%-18s%-15s%-15s%2s%3s%-60s%-20s%-14s"
Formatstring2="%-18s%-15s%-15s%2s%3s%-60s"
# String for printf (used to print LISTEN-ports)
FormatstringListen="%-6s%-6s%-18s%-15s%6s%2s%-17s%-15s"
# UpdateMessage contains the message of weather an update is available och the checksum-check failed
UpdateMessage=""
# OP_LOGG is a log file where all things related to open_ports.sh (install and upgrades) are noted
OP_LOGG="$PREFIX"/OpenPorts_log.txt
# $CountryList is a list (stored locally, comes from http://www.worldatlas.com/aatlas/ctycodes.htm) of all the countries in the world
CountryList="$PREFIX/Countries.txt"
# IP_loggfile is used for debugging. It contains one line per IP lookup, along with PID and time stamp
IP_loggfile=$PREFIX/IP_loggfil.txt



# (Colors can be found at http://en.wikipedia.org/wiki/ANSI_escape_code, http://graphcomp.com/info/specs/ansi_col.html and other sites)
Reset="\e[0m"
ESC="\e["
RES="0"
BoldFace="1"
ItalicFace="3"
UnderlineFace="4"
SlowBlink="5"
BlackBack="40"
RedBack="41"
YellowBack="43"
BlueBack="44"
WhiteBack="47"
BlackFont="30"
RedFont="31"
GreenFont="32"
YellowFont="33"
BlueFont="34"
CyanFont="36"
WhiteFont="37"

# Reset all colors
BGColor="$RES"
Face="$RES"
FontColor="$RES"

# Create LSOF_PATH
if [ -x /usr/sbin/lsof ]; then
  LSOF_PATH="/usr/sbin"
elif [ -x /usr/bin/lsof ]; then
  LSOF_PATH="/usr/bin"
fi


# =================================================================================================================
# =================================================================================================================
# ================================  D A T A   I S   G E N E R A T E D   H E R E  ==================================
# =================================================================================================================
# =================================================================================================================
#
# Create in-data (if run through launchd, $USER = nil or root) and then stop
#
if [ "$USER" = "root" -o -z "$USER" ]; then
  if [ -z "$DEFAULT_INTERFACE" ] ; then
    echo "You have no IP-address. Exiting"
    exit 1
  fi

  # If this is an update run("open_ports.sh -u" and thus fetch_new=t), update!
  if [ "$fetch_new" = "t" ]; then
    [ "$debug" = "t" ] && echo "$(date +%F" "%T); #446; $$; UpdateScript" >> $IP_loggfile
    UpdateScript
  fi

  # If the script is too old, check for update
  # Question 2015-09-18: why is this here at all? This check is also performed in the user section below! /Peter Möller
  if [ -z "$(find $BINDIR/open_ports.sh -type f ${MTIME7d} 2> /dev/null)" ]; then
    [ "$debug" = "t" ] && echo "$(date +%F" "%T); #453; $$; CheckForUpdate" >> $IP_loggfile
    CheckForUpdate
  fi

  printf "Generating datafiles..."

  # Check that the base files exist (otherwise create them and set access rights)
  # (need to use cut to not see extended attributes that will mess up the test)
  if [ ! "$(ls -ls "$FILE4" 2> /dev/null | awk '{ print $2 }' | cut -c1-10)" = "-rw-rw-rw-" ]; then
    mkdir -p $(dirname "$FILE4") 2> /dev/null
    [[ "$OS" = "Darwin" ]] && chgrp -R staff `dirname "$FILE4"`
    chmod 775 $(dirname "$FILE4")
    touch "$FILE4" "$FILE6" "$IP_CACHE" "$IP_LOCATE_CACHE" "$EXTERN" "$FILE_LISTEN"
    #chmod 666 `dirname "$FILE4"`/??*
  fi

  # Check the external IP-adress:
  #  A) has it been updated recently (≤ 60 minutes)
  #  B) is it a reasonably address
  #  C) does it differ from the previously stored $EXTERN
  #  D) if so, remove 127.0.0.1 from $GeoLookupDir (since it's not correct)
  if [ -z "$(find $EXTERN -type f ${MTIME60m} 2> /dev/null)" ]; then
    #echo "$(curl http://tejji.com/ip/my-ip-address.aspx 2> /dev/null | grep -A 1 '<div class="ip_address">' | tail -1 | sed -E 's/<[/]?span[^>]*>//g' | awk '{print $1}')" > /tmp/slaskextern
    #SlaskExtern="$(curl http://tejji.com/ip/my-ip-address.aspx 2> /dev/null | grep -A 1 '<div class="ip_address">' | tail -1 | sed -E 's/<[/]?span[^>]*>//g' | awk '{print $1}' | tr -d '\r\n')"
    # SlaskExtern replaced with simplier call thanks to great feedback from a User op open_ports! :-) I keep the old function for future reference.
    SlaskExtern="$(curl http://ipecho.net/plain 2> /dev/null)"
    [ "$debug" = "t" ] && echo "$(date +%F" "%T); #479; $$; User=\"$USER\"; curl to ipecho.net for external address" >> $IP_loggfile
    # Check to see if this is an IP-address (it should be an empty string after sed if it is)
    if [ -z "$(echo $SlaskExtern | sed 's/[0-9\.]//g')" ]; then
      # If it's different from the stored one; we have moved and need to update $EXTERN
      # and store the external address along with a timestamp in $ExternHistory
      if [ ! "$SlaskExtern" = "$(less $EXTERN 2>/dev/null)" ]; then
        IP="$SlaskExtern"
        if [ -r "${GeoLookupDir}/${IP}.txt" ]; then
          GetCityCountry $IP
        else
          PerformGeoLookup $IP
        fi
        # echo "Add to history file"
        echo "$IP:$Country:$City:`date +%Y-%m-%d, %H.%M`" >> "$ExternHistory"
        echo "$SlaskExtern" > "$EXTERN"
        # Also, create a new file for 127.0.0.1 (since it will be a new one)
        PerformGeoLookup "$(less $EXTERN)"
        echo "$City:$Country" > "${GeoLookupDir}/127.0.0.1.txt"
        # rm $"{GeoLookupDir}/127.0.0.1" 2>/dev/null
      else
        # Touch $EXTERN so it will not check the external address every 2 minutes
        touch "$EXTERN"
      fi
    fi
  fi

  # Checksum check of the "lsof"-command:
  # (the checksum file is created at install time)
  # If checksum file;
  if [ -f "$CHECKSUM" ]; then
    # If checksum file is older than two houres; 
    # Check to see if the checksum of the "losof" command is the same as the stored checksum for "lsof"
    if [ -z "$(find $CHECKSUM -type f ${MTIME120m} 2> /dev/null)" ]; then
      # If NOT the same: create the STOP-file
      if [ ! "$(openssl sha1 $LSOF_PATH/lsof | awk '{ print $2 }')" = "$(less $CHECKSUM)"  ]; then
        touch "$PREFIX"/STOP
      else
        /bin/rm -f "$PREFIX"/STOP 2> /dev/null
      fi
    fi
  else
    # No checksum file found: create it
    echo "$(openssl sha1 $LSOF_PATH/lsof | awk '{ print $2 }')" > "$CHECKSUM"
    /bin/rm -f "$PREFIX"/STOP 2> /dev/null
  fi

  # Create data for ESTABLISHED:
  # Previous capture line. Still here for reference:
  # lsof +c 0 -i 4 -n | grep EST | grep -v "\->127.0.0.1" | sort -f -k 1,1 | cut -d\( -f1 | awk '{ print $1" "$3" "$9 }' | sed 's/\ [[:digit:]].*-\>/\ /g' | sed 's/:/\ /g' | sort -f | uniq -c > $FILE4
  if [ "$OS" = "Darwin" ]; then
    $LSOF_PATH/lsof +c 0 -i 4 -n | grep EST | sort -f -k 1,1 | cut -d\( -f1 | awk '{ print $1" "$3" "$9 }' | sed 's/\ [[:digit:]].*-\>/\ /g' | sed 's/:/\ /g' | sort -f | uniq -c > $FILE4
    # “sanitize” the output by replacing long strings with shorter ones. This started in OS X 10.11 “El Capitan”
    # The following strings are inteded to be cought:
    # - 'com.apple.WebKit.Networking'
    # - 'com.apple.WebKit.WebContent'
    # - '2BUA8C4S2C.com.agilebits.onepas'
    # - '2BUA8C4S2C.com.'
    sed -e 's/com.apple.WebKit.[a-zA-Z]* /Webkit\x20(Safari) /' -e 's/2BUA8C4S2C.com[a-z.]* /1Password /' -i .bak $FILE4

    # The following line is replaced by the one next below after a bug report from Roman Weber. Have not had time to check i thoroughly, though, so it's still here:
    #$LSOF_PATH/lsof +c 0 -i 6 -n | grep EST | grep -v "\->\[\:\:$MY_IP_ADDRESS\]" | sort -f -k 1,1 -k 2,2 | awk '{ print $1" "$3" "$9 }' | sed -E "s/\ \[::[[:digit:]].*-\>\[::/\ /g" | sed "s/\]:/\ /g" | sort -f | uniq -c > $FILE6
    # Something is definetley not right here. Another fix and, I guess, primarily waiting for a couple of 'real' IPv6-catches...
    #$LSOF_PATH/lsof +c 0 -i 6 -n | grep EST | grep -v "\->\[\:\:$MY_IP_ADDRESS\]" | sort -f -k 1,1 -k 2,2 | awk '{ print $1" "$3" "$9 }' | sed -E "s/\ \[.*-\>\[/\ /g" | sed "s/\]:/\ /g" | sort -f | uniq -c > $FILE6
    $LSOF_PATH/lsof +c 0 -i 6 -n | grep EST | sort -f -k 1,1 | cut -d\( -f1 | awk '{ print $1" "$3" "$9 }' | sed 's/\ [[:digit:]].*-\>/\ /g' | sed 's/:/\ /g' | sort -f | uniq -c > $FILE6
  elif [ "$OS" = "Linux" ]; then
    $LSOF_PATH/lsof +c 0 -i 4 -n | grep EST | sort -f -k 1,1 | cut -d\( -f1 | awk '{ print $1" "$3" "$9 }' | sed 's/\ [[:digit:]].*->/\ /g' | sed 's/:/\ /g' | sort -f | uniq -c > $FILE4
    # Have not had access to a linux machine running IPv6 so for Linux we simply skip IPv6 for the time being
    ## $LSOF_PATH/lsof +c 0 -i 6 -n | grep EST | grep -v "->\[\:\:$MY_IP_ADDRESS\]" | sort -f -k 1,1 -k 2,2 | awk '{ print $1" "$3" "$9 }' | sed -E "s/\ \[::[[:digit:]].*->\[::/\ /g" | sed "s/\]:/\ /g" | sort -f | uniq -c > $FILE6
  fi
  # For future development: the ip6-lines to be grep'ed *should* look like this:
  # lsof -n -i 6 | grep EST
  # Screen    56128         peterm    6u  IPv6 0x169caf80      0t0    TCP [fde2:ccd9:7a6b:7089:21e:52ff:fe83:b033]:51199->[fd58:97aa:2e6:277d:217:f2ff:fe04:4228]:vnc-server (ESTABLISHED)
  # (captured ARD-session home)
  # This is how it looks in the other end:
  # AppleVNCS 56767         peterm   11u  IPv6 0x09646d10      0t0    TCP [fd58:97aa:2e6:277d:217:f2ff:fe04:4228]:vnc-server->[fde2:ccd9:7a6b:7089:21e:52ff:fe83:b033]:51199 (ESTABLISHED)


  # Create data for LISTEN:
  if [ "$OS" = "Darwin" ]; then
    $LSOF_PATH/lsof +c 0 -i 4 -n | grep LISTEN | sort -f -k 1,1 | cut -d\( -f1 | awk '{ print "4 - "$1" "$3" "$9 }' | sed 's/:/\ /g' | sed 's/\ [[:digit:]]\{2,5\}$/\ anonymous_port/g' | uniq > /tmp/slask
    $LSOF_PATH/lsof +c 0 -i 6 -n | egrep LISTEN | awk '{ print "- 6 "$1" "$3" "$9 }' | sort -f | sed 's/\ \[.*\]/\ \*/g' | sed 's/:/\ /g' | sed 's/\ [[:digit:]]\{2,5\}$/\ anonymous_port/g' | uniq >> /tmp/slask
    # Clean '1Password'
    sed -e 's/2BUA8C4S2C.com[a-z.]* /1Password /' -i .bak /tmp/slask
  elif [ "$OS" = "Linux" ]; then
    $LSOF_PATH/lsof +c 0 -i 4 -n | grep LISTEN | sort -f -k 1,1 | cut -d\( -f1 | awk '{ print "4 - "$1" "$3" "$9 }' | sed 's/:/\ /g' | sed 's/\ [[:digit:]]\{2,5\}$/\ anonymous_port/g' | uniq > /tmp/slask
    $LSOF_PATH/lsof +c 0 -i 6 -n | egrep LISTEN | awk '{ print "- 6 "$1" "$3" "$9 }' | sort -f | sed 's/\ \[.*\]/\ \*/g' | sed 's/:/\ /g' | sed 's/\ [[:digit:]]\{2,5\}$/\ anonymous_port/g' | uniq >> /tmp/slask
  fi
  # Sort by application:
  less /tmp/slask | sort -f -k 3 > "$FILE_LISTEN"
  # Add a line at the end so that we do not forget the last line during printout
  echo "" >> "$FILE_LISTEN"
  # One can check the IP-address with this sed-line: sed 's/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}:.\{2,15\}->//g' (possible future development)

  # Create a file whose existence tells if the launchd-part of open_ports is running (otherwise warn the user)
  if [ "$OS" = "Darwin" ]; then
    if [ -z "`launchctl list | grep 'se.lth.cs.open_ports'`" ]; then
      touch "$LAUNCHD_FLAG"
    else
      /bin/rm -f "$LAUNCHD_FLAG" 2> /dev/null
    fi
  fi

  # On Mac OS X: see if there is any system software updates
  # Check this every three hours
  if [ "$OS" = "Darwin" ]; then
    if [ -z "`find $SoftUpd -type f -mtime -3h 2> /dev/null`" ]; then
      softwareupdate -l 1> "$SoftUpd" 2> /dev/null
    fi
  fi
 
  # Make sure there is a GeoLookupDir and it has usable permissions. 
  # This could most probably be made much better
  [[ -d "$GeoLookupDir" ]] || mkdir $GeoLookupDir 2>/dev/null
  chmod 777 "$GeoLookupDir" 2> /dev/null
  chmod 666 "$GeoLookupDir/*" 2> /dev/null

  # Make sure the Countries-file exist. Fetch it otherwise
  # This can probably be removed in 2015
  if [ ! -f "$CountryList" ]; then
      curl -s -f -e "$ScriptName ver:$VER" -o /tmp/Countries.txt "$OpenPortsURL"/Countries.txt 2>/dev/null
      curl -s -f -e "$ScriptName ver:$VER" -o /tmp/Countries.txt.sha1 "$OpenPortsURL"/Countries.txt.sha1 2>/dev/null
      ERR=$?
    if [ "$ERR" -eq 0 ] ; then
      if [ "$(openssl sha1 /tmp/Countries.txt | awk '{ print $2 }')" = "$(less /tmp/Countries.txt.sha1)" ]; then
        /bin/mv /tmp/Countries.txt "$CountryList"
        /bin/rm /tmp/Countries.txt.sha1 2>/dev/null
        echo "$(date): The file \"Countries.txt\" was installed" >> "$OP_LOGG"
      fi
    else
      echo "$(date): The \"Countries.txt\" could not be fetched (Err: \"${ERR}\")" >> "$OP_LOGG"
    fi
  fi
  

  # Clean up leftover-files in /tmp
  /bin/rm -f /tmp/"$ScriptName" /tmp/"$ScriptName".sha1 2>/dev/null
  
  printf " Done! (View data by running the script as any other user)\n"
  
  exit 0
fi
# =================================================================================================================
# =================================================================================================================
# ===============================  E N D   O F  D A T A    G E N E R A T I O N    =================================
# =================================================================================================================
# =================================================================================================================
#
#
# Everything below is run by the user


# If the script is too old, check for update
if [ -z "$(find $BINDIR/open_ports.sh -type f ${MTIME7d} 2> /dev/null)" ]; then
  CheckForUpdate
fi


# ----------------------------------------------------------------------------------------------------
#
# Print warnings if something is not right

# Start to check if the file $PREFIX/STOP exists -- if so, "lsof" has been changed and everything must stop!!
if [ -f "$PREFIX"/STOP ]; then
 printf "${ESC}${RedBack};${WhiteFont}mWARNING: \"lsof\" has been changed! You may have been hacked!!!\nLook carefully into this!!!\n$Reset"
 printf "${ESC}${RedBack};${WhiteFont}mLook carefully into this!!!\n$Reset"
 echo
 printf "${ESC}${RedBack};${WhiteFont}mIf you have recently upgraded your system, this is probably the cause.\n$Reset"
 printf "${ESC}${RedBack};${WhiteFont}mIn that case, simply remove the file $CHECKSUM.\n$Reset"
 [[ "$OS" = "Darwin" ]] && say "Warning: l s o f has been changed. You may have been hacked"
 exit 0
fi

# Check if there is any data file: warn the user and quit otherwise
if [ ! -f "$FILE4" ]; then
 printf "${ESC}${RedFont}mWARNING: No datafile! Run the command as \"root\" to generate data! (Or install the \"launchd\"-component)$Reset\n\nWill now exit!\n"
 exit 0
fi

# Check to see if the launchd-part is running. Warn the user otherwise
 if [ "$OS" = "Darwin" ]; then
   if [ -f "$LAUNCHD_FLAG" ]; then
   printf "${ESC}${RedFont}mWARNING: The \"launchd\"-component of \"open_ports.sh\" is NOT RUNNING!!!\n\n$Reset"
   fi
 fi

# Se that the datafiles are created within the last hour. Otherwise tell the user about it!
if [ -z "$(find $FILE4 -type f ${MTIME60m} 2> /dev/null)" ]; then
 printf "${ESC}${RedFont}mWARNING: The datafile is older than 1 hour; make sure the \"launchd\"-component (\"se.lth.cs.open_ports\", located in \"/Library/LaunchDaemons\")\n$Reset"
 printf "${ESC}${RedFont}mis working properly! The information presented here is not current!!$Reset\n\n\n"
fi

# If we don't have an IP-address ($DEFAULT_INTERFACE = "") warn the user!!
if [ -z "$DEFAULT_INTERFACE" ]; then
 printf "${ESC}${RedFont}mWARNING: No IP-address detected!!!\n\n$Reset"
fi

# Find out if is IPv6 is configured
if [ -z "$(/sbin/ifconfig $DEFAULT_INTERFACE | grep inet6)" ]; then
 IPv6="f"
else
 IPv6="t"
fi

# End print warnings
#
# ----------------------------------------------------------------------------------------------------


# Prepare what is to be presented regarding the IP-address (if we are behind a NAT it should be prented)
if [ "$(less $EXTERN)" = "$MY_IP_ADDRESS" ]; then
  IP_ADDRESS_Display="$MY_IP_ADDRESS"
else
  IP_ADDRESS_Display="NAT: $MY_IP_ADDRESS / $(less $EXTERN)"
fi

# Find out which distro we are running
# On Mac OS X, use the command "sw_vers"
# On linux, use the command "lsb_release" if available, otherwise use the file "/etc/issue"
if [ "$OS" = "Darwin" ]; then
  SW_VERS="$(sw_vers | grep ProductName | cut -d: -f2 | tr -d "\t") $(sw_vers | grep ProductVersion | awk '{print $2}')"
  # Find out if it's a server
  # First step: does the name fromsw_vers include "server"?
  if [ -z "$(echo "$SW_VERS" | grep -i server)" ]; then
    # If not, it may still be a server. Beginning with OS X 10.8 all versions include the command serverinfo:
    serverinfo --software 1>/dev/null
    # Exit code 0 = server; 1 = NOT server
    ServSoft=$?
    if [ $ServSoft -eq 0 ]; then
      # Is it configured?
      serverinfo --configured 1>/dev/null
      ServConfigured=$?
      if [ $ServConfigured -eq 0 ]; then
        SW_VERS="$SW_VERS ($(serverinfo --productname) $(serverinfo --shortversion))"
      else
        SW_VERS="$SW_VERS ($(serverinfo --productname) $(serverinfo --shortversion) - unconfigured)"
      fi
    fi
  fi
elif [ "$OS" = "Linux" ]; then
  if [ -x /bin/lsb_release ]; then
    SW_VERS="$(lsb_release -a 2> /dev/null | grep Description | cut -d: -f2 | sed 's/^\t*//g')"
  elif [ -f /etc/issue ]; then
    SW_VERS="$(grep -v "^$" /etc/issue | head -1 | cut -d\\ -f1 | head -1)"
  else
    SW_VERS="Unknown Linux distribution"
  fi
fi


# 
# Print the head

# First, print if there is an update for the script available
printf "$UpdateMessage"
printf "${ESC}${BlackBack};${WhiteFont}mHostname:${ESC}${WhiteBack};${BlackFont}m $(hostname) ($IP_ADDRESS_Display) ${Reset}   ${ESC}${BlackBack};${WhiteFont}mRunning:${ESC}${WhiteBack};${BlackFont}m $SW_VERS ${Reset}   ${ESC}${BlackBack};${WhiteFont}mUptime:${ESC}${WhiteBack};${BlackFont}m $(uptime | cut -d, -f1 | sed -E 's/^.*up\ //g') ${Reset}\n"

# If a Mac, print information about all configured interfaces
[ "$OS" = "Darwin" ] && PrintAllInterfaces

echo
# System Software Update, Mac OS X: 
# Report the available  software updates (from the file/tmp/swu.temp, generated by this script)
# 
# That file typically contains this:
# Software Update Tool
# Copyright 2002-2009 Apple
#
# Software Update found the following new or updated software:
#    * MacOSXUpd10.6.5-10.6.5
#         Mac OS X Update (10.6.5), 505193K [recommended] [restart]
#    * iTunesX-10.1.1
#         iTunes (10.1.1), 91023K [recommended]
#    * XcodeUpdate-3.2.5
#         Xcode Update (3.2.5), 604086K [recommended]
#    * Safari5.0.3SnowLeopard-5.0.3
#         Safari (5.0.3), 38316K [recommended] [restart]
#    * AirPortUtility-5.5.2
#         AirPort Utility (5.5.2), 11990K [recommended]

# From this we will cut away everything but this:
# Mac OS X Update (10.6.5) [restart]
# iTunes (10.1.1)
# Xcode Update (3.2.5)
# Safari (5.0.3) [restart]
# AirPort Utility (5.5.2)
if [ "$OS" = "Darwin" ]; then
  if [ "$(grep 'Software Update found the following new or updated software' $SoftUpd)" ]; then
    printf "${ESC}${BoldFace};${BlackFont};${YellowBack}mThe following software update is available:${Reset}\n${ESC}${YellowFont}m"
    less "$SoftUpd" | egrep -v "^Software Update Tool|^Copyright 2002-2009 Apple|^$" | awk '
      /^\ *\*\ / {
      record="t";next;
      }
      record == "t" { gsub("^[ \t]*","");gsub(", [0-9]*K \\[[^\\]]*\\]","");print "• "$0;record="f";next}'
    printf "${Reset}\n"
  fi
fi

# End print of the head

# |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
# Print the ETSABLISHED-files
for i in 4 6
do
  if [ "$i" = "4" ]; then
    exec 4<"$FILE4"
  else
    exec 6<"$FILE6"
  fi

  # Prepare the date/time-string. Example: “18 Sep 10:29”
  [[ "$OS" = "Darwin" ]] && DATE=$(ls -ls $(dirname "$FILE4"/ip"$i".txt) | awk '{ print $7" "$8" "$9 }')
  [[ "$OS" = "Linux" ]] && DATE=$(ls -ls --time-style=+%Y-%m-%d\ %H:%M $(dirname "$FILE4"/ip"$i".txt) | awk '{ print $7" "$8 }')
  printf "${ESC}${BoldFace}mEstablished IPv$i-connections:$Reset ($DATE)    $(if [ "$i" = "4" ]; then printf "${ESC}${ItalicFace}m(Explanation: Normal$Reset, ${ESC}${GreenFont};${ItalicFace}mSafe protocol$Reset, ${ESC}${CyanFont};${ItalicFace}mAmbiguos DNS$Reset, ${ESC}${RedFont};${ItalicFace}mNo DNS-name$Reset, ${ESC}${RedBack};${WhiteFont};${ItalicFace}mUser is root$Reset${ESC}${ItalicFace}m)$Reset"; fi)\n"
  if [ "$IPv6" = "f" -a "$i" -eq 6 ]; then
    printf "${ESC}${ItalicFace};${YellowFont}mIPv6 is not configured$Reset"
  else
    echo
    # Print different headers if $PREFIX/$GeoLookupKey exist or not
    if [ -n "$GeoLookupKey" ]; then
      printf "${ESC}${UnderlineFace};${YellowFont}m${Formatstring1}${Reset}\n" "Program" "Port" "User" "#" "   " "Hostname $(if [ ! "$DOMAIN" = "" ]; then echo "[.$DOMAIN]"; fi)" "Country" "City"
    else
      printf "${ESC}${UnderlineFace};${YellowFont}m${Formatstring2}${Reset}\n" "Program" "Port" "User" "#" "   " "Hostname $(if [ ! "$DOMAIN" = "" ]; then echo "[.$DOMAIN]"; fi)"
    fi
    if [ -s "$PREFIX/ip$i.txt" ]; then
      while read -u $i COUNT PROGRAM USERR IP PORT
      # Exmple lines:
      # IPv4:    1 2BUA8C4S2C.com. peterm 127.0.0.1 49206
      # IPv6:    1 Screen\x20Sharing peterm 192.168.1.99:63835->130.235.16.211:rfb
      do
        # Zero the colors:
        BGColor="$RES"
        Face="$RES"
        FontColor="$RES"

        # lsof +c 0 replaces " " in application names with "x20"; change back!
        PROGR=`echo $PROGRAM | sed 's/x20/\ /g'`

        # Find out the hostname for $IP. Cut of the trailing dot
        # Gives: $HOSTNAME
        # Also gives PrivateAddress="Yes" if it's a private address (192.168.*.*, 172.16.*.*, 10.*.*.*, 169.254.*.*)
        # (REMOVED) VERY DIRTY: "$(echo $IP | cut -d: -f1)"
        GetDNS "$IP"
#        GetDNS "$(echo $IP | cut -d: -f1)"

        # Find the geo location (also deal with localhost!)
        # If $IP exist in $GeoLookupDir - get the country and city right away
        # otherwise, 
        #   if IP is 127.0.0.1 
        #     AND we are beind a NAT-router (MY_IP_ADDRESS is in the {192.168|172.16|10}-series);
        #       find the external address with whatsmyip.com and store it along with country/city
        #     otherwise
        #       look up the geodata for the default address for the computer
        #   otherwise
        #     look up the IP address and store in the temporary cache
        # get the country and city and store in $IP_CACHE
        # (DIRT REMOVED) VERY DIRTY: "$(echo $IP | cut -d: -f1)"
        if [ -r "${GeoLookupDir}/${IP}.txt" ]; then
          GetCityCountry $IP
        else
          if [ "$IP" = "127.0.0.1" ]; then
            if [ -n "$NAT" ]; then
              PerformGeoLookup "$(less $EXTERN)"
              echo "$City:$Country" > "${GeoLookupDir}/${IP}.txt"
            else
              PerformGeoLookup $MY_IP_ADDRESS
            fi
          else
#            PerformGeoLookup $IP
            PerformGeoLookup "$(echo $IP | cut -d: -f1)"
          fi
        fi

        # Set the colors:
        # If user is root - red background and white text!
        if [ "$USERR" = "root" ]; then
          BGColor="$RedBack"
          FontColor="$WhiteFont"
        fi
        # If it's a safe protocol - green text
        if [ ! -z "$(echo $PORT | egrep 'ssh|https|imaps|smtps|scp|sftp')" -o ! -z "$(echo $PROGRAM | egrep 'sshd')" ]; then
          FontColor="$GreenFont"
        fi
        # No DNS-name AND we are not in a home environment - red text and explain
        if [ -n "$(echo "$HOSTNAME" | grep 'DNS timeout')" -a -z "$NAT" ]; then
          #HOSTNAME="$IP can’t be found in reverse-lookup"
          FontColor="$RedFont"
        fi
        # many answers to the reverse DNS lookup? Blue text and explain
        # Otherwise: print
        if [ "$(echo $HOSTNAME | wc -w)" -gt "1" -a -z "$(echo $HOSTNAME | grep 'DNS timeout')" -a "$PrivateAddress" = "No" ]; then
          FontColor="$CyanFont"
          HOSTN="$IP = \"$(echo $HOSTNAME | awk '{ print $1 }')\" and `echo $(( $(echo $HOSTNAME | wc | awk '{ print $2 }') - 1 ))` more names"
          HOSTNAME="$HOSTN"
        fi
        # If background is red AND text is red? Blink with white text!
        if [ "$BGColor" = "41" -a "$FontColor" = "31" ]; then
          FontColor="$WhiteFont"
          Face="$SlowBlink"
        fi
        # Print the line!
        if [ -n "$GeoLookupKey" ]; then
          printf "${ESC}${Face};${BGColor};${FontColor}m$Formatstring1$Reset\n" "$PROGR" "$PORT" "$USERR" "$COUNT" "   " "${HOSTNAME//.$DOMAIN}" "$Country" "$City"
        else
          printf "${ESC}${Face};${BGColor};${FontColor}m$Formatstring2$Reset\n" "$PROGR" "$PORT" "$USERR" "$COUNT" "   " "${HOSTNAME//.$DOMAIN}"
        fi
     done
   else
     echo "No established IPv$i-connections"
   fi
 fi
 echo
 echo
done

# End print of ESTABLISHED
# |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||



# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Print the LISTEN-file
LastIPv4=""
LastIPv6=""
LastProgram=""
LastUser=""
LastRange=""
LastPort=""
exec 5<"$FILE_LISTEN"
if [ -s "$FILE_LISTEN" ]; then
[[ "$OS" = "Darwin" ]] && DATE=$(ls -ls "$FILE_LISTEN" | awk '{ print $7" "$8" "$9 }')
[[ "$OS" = "Linux" ]] && DATE=$(ls -ls --time-style=+%Y-%m-%d\ %H:%M "$FILE_LISTEN" | awk '{ print $7" "$8 }')
printf "\n\n${ESC}${BoldFace}mListening ports:$Reset ($DATE)\n\n"
printf "${ESC}${UnderlineFace};${YellowFont}m$FormatstringListen$Reset\n" "IPv4" "IPv6" "Program" "User" "Port#" " " "PortName" "Servicerange"
while read -u 5 IPv4 IPv6 PROGRAM USERR RANGE PORT
do
  # Reset the colors:
  BGColor="$RES"
  Face="$RES"
  FontColor="$RES"

  PROGR=`echo $PROGRAM | sed 's/x20/\ /g'`
  # If the lines are the same: do nothing more than to set both 4 and 6 when it is to be printed the next turn around
  if [[ "$LastProgram" = "$PROGR" && "$LastUser" = "$USERR" && "$LastPort" = "$PORT" && "$LastRange" = "$RANGE" ]]; then
    export LastIPv4="4"
    export LastIPv6="6"
  else
    # This turn is will be printed

    # If LastProgram is NOT empty (then assume the other are as well; first turn around - do not print!)
    # the choose colors
    if [ ! -z "$LastProgram" ]; then
      # If user is root - red background and white text!
      if [ "$LastUser" = "root" ]; then
        BGColor="$RedBack"
        FontColor="$WhiteFont"
      fi
      # Safe protocol - green text
      if [ ! -z "`echo $LastPort | egrep 'ssh|https|imaps|smtps|scp|sftp'`" -o ! -z "`echo $LastProgram | egrep 'sshd'`" ]; then
        FontColor="$GreenFont"
      fi
      # Print!!
      printf "${ESC}${BGColor};${FontColor}m$FormatstringListen$Reset\n" "$LastIPv4" "$LastIPv6" "$LastProgram" "$LastUser" "`grep "^$LastPort\b" /etc/services | head -1 | awk '{ print $2 }' | cut -d/ -f1`" " " "`echo $LastPort | sed 's/_/\ /g'`" "$LastRange"
    fi
    LastIPv4="$IPv4"
    LastIPv6="$IPv6"
  fi
  LastProgram="$PROGR"
  LastUser="$USERR"
  LastPort="$PORT"
  LastRange="$RANGE"
done
else
echo "No ports open for listening"
fi

# End print of LISTEN
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

exit 0

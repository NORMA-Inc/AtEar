#!/bin/bash
# Init
set -e

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "You must be a root user" 2>&1
    exit 1
fi
    echo "Install started"

# Install started
if [ $(dpkg-query -W -f='${Status}' aircrack-ng 2>/dev/null | grep -c "ok installed") -eq 0 ];
then
    echo "Install packages aircrack-ng"
    sudo apt-get --force-yes --yes install aircrack-ng
fi
if [ $(dpkg-query -W -f='${Status}' tshark 2>/dev/null | grep -c "ok installed") -eq 0 ];
then
    echo "Install packages tshark"
    sudo apt-get --force-yes --yes install tshark
fi
if [ $(dpkg-query -W -f='${Status}' hostapd 2>/dev/null | grep -c "ok installed") -eq 0 ];
then
    echo "Install packages hostapd"
    sudo apt-get --force-yes --yes install hostapd
fi
if [ $(dpkg-query -W -f='${Status}' python-dev 2>/dev/null | grep -c "ok installed") -eq 0 ];
then
    echo "Installed packages python-dev"
    sudo apt-get --force-yes --yes install python-dev
fi
if [ $(dpkg-query -W -f='${Status}' python-pip 2>/dev/null | grep -c "ok installed") -eq 0 ];
then
    echo "Installed packages python-pip"
    sudo apt-get --force-yes --yes install python-pip
fi
if [ $(dpkg-query -W -f='${Status}' python-pyodbc 2>/dev/null | grep -c "ok installed") -eq 0 ];
then
    echo "Installed packages python-pyodbc"
    sudo apt-get --force-yes --yes install python-pyodbc
fi
echo "Installed requirements python packages"
sudo pip install -r requirements.txt
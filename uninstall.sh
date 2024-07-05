#!/bin/bash

# Ensure the script is being run with root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Remove the legionnaire script from /usr/local/bin
echo "Removing legionnaire tool..."
rm -f /usr/local/bin/legionnaire

# Uninstall the Python libraries installed via requirements.txt
echo "Uninstalling Python libraries..."
pip3 uninstall -y termcolor pyfiglet prettytable requests

# Confirm uninstallation
echo "Legionnaire has been uninstalled."

#!/bin/bash

# Ensure the script is being run with root privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Install necessary packages
echo "Installing required packages..."
apt-get update
apt-get install -y python3 python3-pip

# Install required Python libraries from requirements.txt
echo "Installing required Python libraries..."
pip3 install -r requirements.txt

# Ensure the legionnaire.py script is executable
chmod +x legionnaire.py

# Move the legionnaire script to /usr/local/bin and rename it
cp legionnaire.py /usr/local/bin/legionnaire

# Make sure it is executable
chmod +x /usr/local/bin/legionnaire

# Confirm installation
echo "Legionnaire has been installed. You can run it by typing 'legionnaire' in the terminal."

#!/bin/bash

# Update and install necessary packages
sudo apt update
sudo apt install -y git python3 python3-pip python3-virtualenv apache2 libapache2-mod-php mariadb-server redis-server

# Clone the MISP repository if not already cloned
cd /var/www/
if [ ! -d "MISP" ]; then
    sudo git clone https://github.com/MISP/MISP.git
fi

# Install MISP Python dependencies
cd /var/www/MISP
sudo pip3 install -r /var/www/MISP/requirements.txt

# Set permissions for the MISP directory
sudo chown -R www-data:www-data /var/www/MISP
sudo chmod -R 755 /var/www/MISP

# Set up the MISP configuration file (edit the base URL and other settings as needed)
sudo cp /var/www/MISP/INSTALL/config.php.dist /var/www/MISP/app/Config/config.php

# Configure the MISP database (if not already set up)
# Please make sure that your database is already configured
sudo mysql -u root -e "CREATE DATABASE misp; CREATE USER 'mispuser'@'localhost' IDENTIFIED BY 'misp_password'; GRANT ALL PRIVILEGES ON misp.* TO 'mispuser'@'localhost'; FLUSH PRIVILEGES;"

# Configure Redis for MISP
echo "bind 127.0.0.1 ::1" | sudo tee -a /etc/redis/redis.conf
sudo systemctl restart redis-server

# Configure Apache2 for MISP
sudo a2enmod rewrite
sudo a2enmod headers
sudo a2ensite 000-default
sudo systemctl restart apache2

# Create MISP API key (for interaction with external systems)
API_KEY=$(openssl rand -hex 32)
echo "MISP API key generated: $API_KEY"

# Store the API key securely (for example, in Key Vault or a secure place)
# For demonstration purposes, we'll create a file to store the API key
echo "API_KEY=$API_KEY" | sudo tee /var/www/MISP/config/api_key.conf

# Print out the MISP API URL and key location
echo "MISP API URL: http://localhost/events/restSearch"
echo "API Key: $API_KEY"
echo "API key has been stored in /var/www/MISP/config/api_key.conf"

# Optionally, set up CRON jobs or other automation for CIRCL feeds (if needed)
# Example for running a script to pull feeds every 10 minutes
# sudo crontab -l | { cat; echo "*/10 * * * * /var/www/MISP/feeds/your_feed_script.sh"; } | sudo crontab -

echo "MISP API has been configured."

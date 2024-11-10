#!/bin/bash

# Install Docker and MISP container
sudo apt update
sudo apt install -y docker.io
sudo systemctl enable --now docker

# Install Git
sudo apt install -y git

# Clone git MISP
git clone git@github.com:MISP/misp-docker.git
cp temnplate.env .env
docker compose pull
docker compuose up
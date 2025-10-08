#!/bin/bash
sudo apt-get install libssl-dev
gcc -o secrets_manager secrets_manager.c -lssl -lcrypto
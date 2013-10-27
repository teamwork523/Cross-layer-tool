#!/bin/bash

# install easy install
if [ $(command -v easy_install) == "" ]; then 
    sudo apt-get install python-setuptools
fi
sudo easy_install pytz-2013.7-py2.7.egg

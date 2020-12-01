#!/usr/bin/env bash
while read -r "line"; do declare  "$line"; done < settings.cfg
sudo hciconfig $device up piscan

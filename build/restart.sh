#!/bin/bash

pgrep myzk | xargs kill

sleep 2


nohup ./bin/myzk  -l 192.168.136.90:2311 > myzk.log 2>&1 &

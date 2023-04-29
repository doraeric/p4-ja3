#!/bin/bash
set -e

sudo id
CWD=`pwd`
mn_host_pid=()
for i in {1..2}; do
    mn_host_pid[$i]=`pgrep -f "is mininet:h$i\b"`
done

defense=$1
monitor_time=160
attack_time=150

# client
sudo nsenter -a -t ${mn_host_pid[2]} python3 /cwd/30-loop-req.py

# https://stackoverflow.com/questions/356100/
for job in `jobs -p`; do
    echo wait pid $job
    wait $job || let "FAIL+=1"
done

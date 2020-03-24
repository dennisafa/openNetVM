#!/bin/bash

sh go.sh 0,1,2,3 3 0xF8 -a 0x7f000000000 -s stdout -c
sh ../examples/tcp_monitor/go.sh 1
sudo /home/dennisafa/mtcp/apps/example/epserver -N 1 -p www -f epserver.conf
sh ../examples/simple_forward/go.sh 3 -d 3

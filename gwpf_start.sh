#!/bin/sh -x

#echo ffffffff > /sys/class/net/eth0/queues/rx-0/rps_cpus
#echo ffffffff > /sys/class/net/eth0/queues/rx-1/rps_cpus
#echo 32768 > /sys/class/net/eth0/queues/rx-0/rps_flow_cnt
#echo 32768 > /sys/class/net/eth0/queues/rx-1/rps_flow_cnt
#echo ffffffff > /sys/class/net/eth1/queues/rx-0/rps_cpus
#echo ffffffff > /sys/class/net/eth1/queues/rx-1/rps_cpus
#echo 32768 > /sys/class/net/eth1/queues/rx-0/rps_flow_cnt
#echo 32768 > /sys/class/net/eth1/queues/rx-1/rps_flow_cnt
#echo 65536 > /proc/sys/net/core/rps_sock_flow_entries

if [ -e /sys/class/net/eth0/queues/rx-0/rps_cpus ]
then
echo ffffffff > /sys/class/net/eth0/queues/rx-0/rps_cpus
fi

if [ -e /sys/class/net/eth0/queues/rx-1/rps_cpus ]
then
echo ffffffff > /sys/class/net/eth0/queues/rx-1/rps_cpus
fi

if [ -e /sys/class/net/eth0/queues/rx-0/rps_flow_cnt ]
then
echo 32768 > /sys/class/net/eth0/queues/rx-0/rps_flow_cnt
fi

if [ -e /sys/class/net/eth0/queues/rx-1/rps_flow_cnt ]
then
echo 32768 > /sys/class/net/eth0/queues/rx-1/rps_flow_cnt
fi

if [ -e /sys/class/net/eth1/queues/rx-0/rps_cpus ]
then
echo ffffffff > /sys/class/net/eth1/queues/rx-0/rps_cpus
fi

if [ -e /sys/class/net/eth1/queues/rx-1/rps_cpus ]
then
echo ffffffff > /sys/class/net/eth1/queues/rx-1/rps_cpus
fi

if [ -e /sys/class/net/eth1/queues/rx-0/rps_flow_cnt ]
then
echo 32768 > /sys/class/net/eth1/queues/rx-0/rps_flow_cnt
fi

if [ -e /sys/class/net/eth1/queues/rx-1/rps_flow_cnt ]
then
echo 32768 > /sys/class/net/eth1/queues/rx-1/rps_flow_cnt
fi

if [ -e /proc/sys/net/core/rps_sock_flow_entries ]
then
echo 65536 > /proc/sys/net/core/rps_sock_flow_entries
fi

service irqbalance stop

/sbin/iptables -t mangle -A PREROUTING -d 10.0.0.0/8 -j GTPU --own-ip 0.0.0.0 --own-tun 100 --peer-ip 0.0.0.0 --peer-tun 101 --action add
/sbin/iptables -t mangle -A PREROUTING  -p udp --dport 2152 -j GTPU --action remove

exit 0
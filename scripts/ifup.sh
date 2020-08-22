brctl addbr br0
ip a add 10.0.3.1/24 dev br0
ip link set br0 up


ip a add 10.0.3.2/24 dev eth2
ip link set eth2 up


tunctl -t tap0 -u `whoami`
ip link set tap0 up

brctl addif br0 tap0
brctl addif br0 eth2


echo "1" > /proc/sys/net/ipv4/ip_forward

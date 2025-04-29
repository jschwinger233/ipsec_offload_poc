source ./lib.sh

ip -all net d
for i in 0 1; do
    echo $i > /sys/bus/netdevsim/del_device
done

sleep 1

algo="aead rfc4106(gcm(aes)) 0x3132333435363738393031323334353664636261 128"
srcip=10.244.1.117
dstip=10.244.2.58

# === nodes

ip netns add node1
ip netns add node2

ip link add veth-node1 type veth peer name veth-node2

ip link set veth-node1 netns node1
ip link set veth-node2 netns node2

ip netns exec node1 ip link set veth-node1 up
ip netns exec node2 ip link set veth-node2 up

#ip netns exec node1 ping -c 1 $dstip || exit 1

# === netdevsim

if ! mount | grep -q debugfs; then
	mount -t debugfs none /sys/kernel/debug/ &> /dev/null
fi

if [ ! -w /sys/bus/netdevsim/new_device ] ; then
	modprobe -q netdevsim
	if [ $? -ne 0 ]; then
		echo "SKIP: can't load netdevsim for ipsec offload"
		exit $ksft_skip
	fi
fi

create_netdevsim() {
    local id="$1"
    local ns="$2"

    modprobe netdevsim &> /dev/null
    udevadm settle

    echo "$id" | ip netns exec $ns tee /sys/bus/netdevsim/new_device >/dev/null
    local dev=$(ip netns exec $ns ls /sys/bus/netdevsim/devices/netdevsim$id/net)
    ip -netns $ns link set dev $dev name nsim$id
    ip -netns $ns link set dev nsim$id up

    echo nsim$id
}

create_netdevsim 0 node1
create_netdevsim 1 node2

# === nsim

ip -n node1 addr add $srcip/24 dev nsim0
ip -n node1 r a ${dstip%.*}.0/24 dev nsim0
ip -n node1 n r $dstip dev nsim0 lladdr $(ip -n node2 -br l sh nsim1 | awk '{print $3}') nud permanent

ip -n node2 addr add $dstip/24 dev nsim1
ip -n node2 n r $srcip dev nsim1 lladdr $(ip -n node1 -br l sh nsim0 | awk '{print $3}') nud permanent
ip net e node2 sysctl net.ipv4.conf.nsim1.rp_filter=0
ip net e node2 sysctl net.ipv4.conf.all.rp_filter=0

# === xfrm (offload)
ip -n node1 x p a src 0.0.0.0/0 dst 10.244.2.0/24 dir out priority 0 mark 0x9daa3e00 mask 0xffffff00 tmpl src $srcip dst $dstip proto esp spi 0x00000003 reqid 1 mode tunnel

ip -n node1 x s a src $srcip dst $dstip proto esp spi 0x00000003 reqid 1 mode tunnel mark 0x9daa3e00 mask 0xffffff00 output-mark 0xe00 mask 0xffffff00 aead 'rfc4106(gcm(aes))' 0xb82490e443b1f6cbdfb26b23d033d89fde2c5fdd 128 offload dev nsim0 dir out

ip -n node2 x p a src 0.0.0.0/0 dst 0.0.0.0/0 dir in priority 0 tmpl src 0.0.0.0 dst 0.0.0.0 proto esp reqid 0 mode tunnel level use

ip -n node2 x s a src $srcip dst $dstip proto esp spi 0x00000003 reqid 1 mode tunnel aead 'rfc4106(gcm(aes))' 0xb82490e443b1f6cbdfb26b23d033d89fde2c5fdd 128

# === nf

ip net e node1 iptables -t mangle -A OUTPUT -p icmp -j MARK --set-mark 0x9daa3e00

# === bpf redirect

ifindex_nsim0=$(ip -n node1 -j link show nsim0 | jq -r '.[0].ifindex')
ifindex_nsim1=$(ip -n node2 -j link show nsim1 | jq -r '.[0].ifindex')
ifindex_veth_node1=$(ip -n node1 -j link show veth-node1 | jq -r '.[0].ifindex')
ifindex_veth_node2=$(ip -n node2 -j link show veth-node2 | jq -r '.[0].ifindex')

clang -g -O2 -target bpf -Wall -c bpf.c -o node1.o -D IFINDEX_NSIM=$ifindex_nsim0 -D IFINDEX_VETH=$ifindex_veth_node1
clang -g -O2 -target bpf -Wall -c bpf.c -o node2.o -D IFINDEX_NSIM=$ifindex_nsim1 -D IFINDEX_VETH=$ifindex_veth_node2

ip net e node1 tc qdisc add dev nsim0 clsact
ip net e node1 tc qdisc add dev veth-node1 clsact
ip net e node2 tc qdisc add dev veth-node2 clsact
ip net e node2 tc qdisc add dev nsim1 clsact

ip net e node1 tc filter add dev nsim0 egress bpf da obj node1.o sec nsim2veth
ip net e node1 tc filter add dev veth-node1 ingress bpf da obj node1.o sec veth2nsim

ip net e node2 tc filter add dev nsim1 egress bpf da obj node1.o sec nsim2veth
ip net e node2 tc filter add dev veth-node2 ingress bpf da obj node1.o sec veth2nsim


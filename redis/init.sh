#!/bin/bash

# a shell script for initialize redis-cluster for dev environment.

kubectl run -it ubuntu --image=ubuntu:22.04 --restart=Never /bin/bash

# after entry the ubuntu container, run the following commands.

apt update

apt install wget -y && apt install dnsutils -y && apt install gcc -y && apt install make -y

wget http://download.redis.io/releases/redis-7.0.0.tar.gz

tar -zxvf redis-7.0.0.tar.gz

cd redis-7.0.0 && make

# redis-0.redis-service.default.svc.cluster.local
nslookup redis-service.default.svc.cluster.local

# now you can get 6 ip address, and we set front 3 for master, back 3 for slave.

src/redis-cli --cluster create <ip1>:6379 <ip2>:6379 <ip3>:6379

# there will be 3 master ids generated

src/redis-cli --cluster add-node <ip4>:6379 <ip1>:6379 --cluster-slave --cluster-master-id <master-id1>

src/redis-cli --cluster add-node <ip5>:6379 <ip2>:6379 --cluster-slave --cluster-master-id <master-id2>

src/redis-cli --cluster add-node <ip6>:6379 <ip3>:6379 --cluster-slave --cluster-master-id <master-id3>

# now you can get 3 master and 3 slave nodes.

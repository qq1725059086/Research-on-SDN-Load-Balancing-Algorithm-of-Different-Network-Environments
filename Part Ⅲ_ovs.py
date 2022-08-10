ovs-vsctl -- set Port s1-eth2 qos=@newqos1 \
     -- --id=@newqos1 create QoS type=linux-htb queues=0=@q0\
     -- --id=@q0 create Queue other-config:min-rate=1000000 other-config:max-rate=90000000
 
ovs-vsctl -- set Port s1-eth3 qos=@newqos2\
     -- --id=@newqos2 create QoS type=linux-htb queues=0=@q0\
     -- --id=@q0 create Queue other-config:min-rate=1000000 other-config:max-rate=100000000
ovs-vsctl -- set Port s1-eth3 qos=@newqos3\
     -- --id=@newqos3 create QoS type=linux-htb queues=1=@q1\
     -- --id=@q1 create Queue other-config:min-rate=5000000 other-config:max-rate=200000000     
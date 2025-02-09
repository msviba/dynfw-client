# PF implementation (FreeBSD)

## Description

Every blacklisted IPs will be added to pf table *sentinel-bl*.
Root permition is required (pfctl).

It uses those commands:
+ `/sbin/pfctl -t sentinel-bl -T add $positiveIp`
+ `/sbin/pfctl -t sentinel-bl -T del $negativeIp`

## Instalation

`pkg install py311-pyzmq py311-msgpack`

## PF configuration


```
    table <sentinel-bl> persist

    # some yours rules and better whitelist your IPs
    pass in quick proto tcp from <whitelist> to any port {ssh} flags S/SA modulate state
    pass in quick proto udp from <whitelist> port = 500 to any port = 500
    pass in quick on $ext_if proto esp from <whitelist> to any
    pass in quick on $ext_if proto ah from <whitelist> to any
    
    # block blacklisted IPs
    block in quick on $ext_if from <sentinel-bl> to any
```

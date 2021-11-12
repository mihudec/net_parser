import unittest

from net_parser.ops.BaseOpsParsers import *

from tests import BaseNetParserTest


class TestBaseOpsParser(BaseNetParserTest):

    pass


class TestCdpNeighborDetailParser(BaseNetParserTest):

    pass

class TestOpsParser(BaseNetParserTest):


    cdp_text = """
-------------------------
Device ID: CORE-Router.a1.lab
Entry address(es): 
  IP address: 10.8.8.71
Platform: Linux Unix,  Capabilities: Router Source-Route-Bridge 
Interface: Ethernet1/3,  Port ID (outgoing port): Ethernet0/1
Holdtime : 133 sec

Version :
Cisco IOS Software, Linux Software (I86BI_LINUX-ADVENTERPRISEK9-M), Version 15.7(3)M2, DEVELOPMENT TEST SOFTWARE
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2018 by Cisco Systems, Inc.
Compiled Wed 28-Mar-18 11:18 by prod_rel_team

advertisement version: 2
Management address(es): 
  IP address: 10.8.8.71

-------------------------
Device ID: CZ-OF1-SW-LAB10.alef.lab
Entry address(es): 
  IP address: 10.8.8.3
Platform: cisco WS-C2960X-48TS-L,  Capabilities: Switch IGMP 
Interface: Ethernet1/3,  Port ID (outgoing port): GigabitEthernet1/0/15
Holdtime : 144 sec

Version :
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(2)E3, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2015 by Cisco Systems, Inc.
Compiled Wed 26-Aug-15 07:12 by prod_rel_team

advertisement version: 2
Protocol Hello:  OUI=0x00000C, Protocol ID=0x0112; payload len=27, value=00000000FFFFFFFF010221FF00000000000000562BCE4E00FF0000
VTP Management Domain: ''
Native VLAN: 1000
Duplex: full
Management address(es): 
  IP address: 10.8.8.3

-------------------------
Device ID: OOB-Router.a1.lab
Entry address(es): 
  IP address: 10.8.8.159
Platform: Linux Unix,  Capabilities: Router Source-Route-Bridge 
Interface: Ethernet1/3,  Port ID (outgoing port): Ethernet0/1
Holdtime : 176 sec

Version :
Cisco IOS Software, Linux Software (I86BI_LINUX-ADVENTERPRISEK9-M), Version 15.7(3)M2, DEVELOPMENT TEST SOFTWARE
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2018 by Cisco Systems, Inc.
Compiled Wed 28-Mar-18 11:18 by prod_rel_team

advertisement version: 2
Management address(es): 
  IP address: 10.8.8.159

-------------------------
Device ID: OOB-Router.a1.lab
Entry address(es): 
  IP address: 192.168.0.1
Platform: Linux Unix,  Capabilities: Router Source-Route-Bridge 
Interface: Ethernet1/0,  Port ID (outgoing port): Ethernet0/0
Holdtime : 131 sec

Version :
Cisco IOS Software, Linux Software (I86BI_LINUX-ADVENTERPRISEK9-M), Version 15.7(3)M2, DEVELOPMENT TEST SOFTWARE
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2018 by Cisco Systems, Inc.
Compiled Wed 28-Mar-18 11:18 by prod_rel_team

advertisement version: 2
Management address(es): 
  IP address: 192.168.0.1


Total cdp entries displayed : 4
"""

    interfaces_text = """
Ethernet0/0 is up, line protocol is up (connected) 
  Hardware is Ethernet, address is aabb.cc00.3e00 (bia aabb.cc00.3e00)
  MTU 1500 bytes, BW 10000 Kbit/sec, DLY 1000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full-duplex, Auto-speed, media type is RJ45
  input flow-control is off, output flow-control is unsupported 
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:00, output 00:00:01, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue: 0/0 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     264854 packets input, 83169014 bytes, 0 no buffer
     Received 7 broadcasts (0 multicasts)
     0 runts, 0 giants, 0 throttles 
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 input packets with dribble condition detected
     1079736 packets output, 143877792 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 unknown protocol drops
     0 babbles, 0 late collision, 0 deferred
     0 lost carrier, 0 no carrier
     0 output buffer failures, 0 output buffers swapped out
Ethernet0/1 is up, line protocol is up (connected) 
  Hardware is Ethernet, address is aabb.cc00.3e10 (bia aabb.cc00.3e10)
  MTU 1500 bytes, BW 10000 Kbit/sec, DLY 1000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full-duplex, Auto-speed, media type is RJ45
  input flow-control is off, output flow-control is unsupported 
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:02, output 00:00:00, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue: 0/0 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     264861 packets input, 83171338 bytes, 0 no buffer
     Received 7 broadcasts (0 multicasts)
     0 runts, 0 giants, 0 throttles 
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 input packets with dribble condition detected
     1079695 packets output, 143859604 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 unknown protocol drops
     0 babbles, 0 late collision, 0 deferred
     0 lost carrier, 0 no carrier
     0 output buffer failures, 0 output buffers swapped out
Ethernet0/2 is up, line protocol is up (connected) 
  Hardware is Ethernet, address is aabb.cc00.3e20 (bia aabb.cc00.3e20)
  MTU 1500 bytes, BW 10000 Kbit/sec, DLY 1000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full-duplex, Auto-speed, media type is RJ45
  input flow-control is off, output flow-control is unsupported 
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input never, output 00:00:00, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue: 0/0 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 packets input, 0 bytes, 0 no buffer
     Received 0 broadcasts (0 multicasts)
     0 runts, 0 giants, 0 throttles 
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 input packets with dribble condition detected
     1344550 packets output, 227028851 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 unknown protocol drops
     0 babbles, 0 late collision, 0 deferred
     0 lost carrier, 0 no carrier
     0 output buffer failures, 0 output buffers swapped out
Ethernet0/3 is up, line protocol is up (connected) 
  Hardware is Ethernet, address is aabb.cc00.3e30 (bia aabb.cc00.3e30)
  MTU 1500 bytes, BW 10000 Kbit/sec, DLY 1000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full-duplex, Auto-speed, media type is RJ45
  input flow-control is off, output flow-control is unsupported 
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input never, output 00:00:00, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue: 0/0 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 packets input, 0 bytes, 0 no buffer
     Received 0 broadcasts (0 multicasts)
     0 runts, 0 giants, 0 throttles 
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 input packets with dribble condition detected
     1344556 packets output, 227031629 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 unknown protocol drops
     0 babbles, 0 late collision, 0 deferred
     0 lost carrier, 0 no carrier
     0 output buffer failures, 0 output buffers swapped out
Ethernet1/0 is up, line protocol is up (connected) 
  Hardware is Ethernet, address is aabb.cc00.3e01 (bia aabb.cc00.3e01)
  Internet address is 192.168.1.114/24
  MTU 1500 bytes, BW 10000 Kbit/sec, DLY 1000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full-duplex, Auto-speed, media type is RJ45
  input flow-control is off, output flow-control is unsupported 
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:07, output 00:00:43, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue: 0/40 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     98825 packets input, 15338412 bytes, 0 no buffer
     Received 91926 broadcasts (0 IP multicasts)
     0 runts, 0 giants, 0 throttles 
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 input packets with dribble condition detected
     40352 packets output, 13202454 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 unknown protocol drops
     0 babbles, 0 late collision, 0 deferred
     0 lost carrier, 0 no carrier
     0 output buffer failures, 0 output buffers swapped out
Ethernet1/1 is up, line protocol is up (connected) 
  Hardware is Ethernet, address is aabb.cc00.3e11 (bia aabb.cc00.3e11)
  MTU 1500 bytes, BW 10000 Kbit/sec, DLY 1000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full-duplex, Auto-speed, media type is RJ45
  input flow-control is off, output flow-control is unsupported 
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:04:21, output 00:00:01, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue: 0/0 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     768 packets input, 53760 bytes, 0 no buffer
     Received 0 broadcasts (0 multicasts)
     0 runts, 0 giants, 0 throttles 
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 input packets with dribble condition detected
     721878 packets output, 53725957 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 unknown protocol drops
     0 babbles, 0 late collision, 0 deferred
     0 lost carrier, 0 no carrier
     0 output buffer failures, 0 output buffers swapped out
Ethernet1/2 is up, line protocol is up (connected) 
  Hardware is Ethernet, address is aabb.cc00.3e21 (bia aabb.cc00.3e21)
  MTU 1500 bytes, BW 10000 Kbit/sec, DLY 1000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full-duplex, Auto-speed, media type is RJ45
  input flow-control is off, output flow-control is unsupported 
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:56:47, output 00:00:00, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue: 0/0 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     768 packets input, 53760 bytes, 0 no buffer
     Received 0 broadcasts (0 multicasts)
     0 runts, 0 giants, 0 throttles 
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 input packets with dribble condition detected
     721888 packets output, 53730587 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 unknown protocol drops
     0 babbles, 0 late collision, 0 deferred
     0 lost carrier, 0 no carrier
     0 output buffer failures, 0 output buffers swapped out
Ethernet1/3 is up, line protocol is up (connected) 
  Hardware is Ethernet, address is aabb.cc00.3e31 (bia aabb.cc00.3e31)
  Internet address will be negotiated using DHCP
  MTU 1500 bytes, BW 10000 Kbit/sec, DLY 1000 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive set (10 sec)
  Full-duplex, Auto-speed, media type is RJ45
  input flow-control is off, output flow-control is unsupported 
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input 00:00:00, output 00:00:00, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue: 0/40 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     891512 packets input, 83237850 bytes, 0 no buffer
     Received 885006 broadcasts (0 IP multicasts)
     0 runts, 0 giants, 0 throttles 
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 input packets with dribble condition detected
     77760 packets output, 29409687 bytes, 0 underruns
     0 output errors, 0 collisions, 0 interface resets
     0 unknown protocol drops
     0 babbles, 0 late collision, 0 deferred
     0 lost carrier, 0 no carrier
     0 output buffer failures, 0 output buffers swapped out
Vlan1 is administratively down, line protocol is down 
  Hardware is Ethernet SVI, address is aabb.cc80.3e00 (bia aabb.cc80.3e00)
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive not supported 
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue: 0/40 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 packets input, 0 bytes, 0 no buffer
     Received 0 broadcasts (0 IP multicasts)
     0 runts, 0 giants, 0 throttles 
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 packets output, 0 bytes, 0 underruns
     0 output errors, 0 interface resets
     0 unknown protocol drops
     0 output buffer failures, 0 output buffers swapped out
Vlan10 is administratively down, line protocol is down 
  Hardware is Ethernet SVI, address is aabb.cc80.3e00 (bia aabb.cc80.3e00)
  Description: FooBar
  MTU 1500 bytes, BW 1000000 Kbit/sec, DLY 10 usec, 
     reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, loopback not set
  Keepalive not supported 
  ARP type: ARPA, ARP Timeout 04:00:00
  Last input never, output never, output hang never
  Last clearing of "show interface" counters never
  Input queue: 0/75/0/0 (size/max/drops/flushes); Total output drops: 0
  Queueing strategy: fifo
  Output queue: 0/40 (size/max)
  5 minute input rate 0 bits/sec, 0 packets/sec
  5 minute output rate 0 bits/sec, 0 packets/sec
     0 packets input, 0 bytes, 0 no buffer
     Received 0 broadcasts (0 IP multicasts)
     0 runts, 0 giants, 0 throttles 
     0 input errors, 0 CRC, 0 frame, 0 overrun, 0 ignored
     0 packets output, 0 bytes, 0 underruns
     0 output errors, 0 interface resets
     0 unknown protocol drops
     0 output buffer failures, 0 output buffers swapped out

"""

    def test_init_subclass(self):
        print(OpsParser._registry)

        cdp_parser = OpsParser(vendor='ios', command='show cdp neighbors detail')
        print(cdp_parser)
        results = cdp_parser.parse(text=self.cdp_text)
        for result in results:
            print(result)

        interface_parser = OpsParser(vendor='ios', command='show interfaces')
        print(interface_parser)
        results = interface_parser.parse(text=self.interfaces_text)
        for result in results:
            print(result)

del BaseNetParserTest

if __name__ == '__main__':
    unittest.main()
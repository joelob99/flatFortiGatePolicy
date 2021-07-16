# FlatFortiGatePolicy

**No warranty of any kind: use at your own risk.**

## Summary

Because complicated firewall policies can not understand easily, it is often desired to convert to simple. In some cases, that is requested from the configuration file. This script flattens firewall policies of the FortiGate configuration. Also, it can look up the specified addresses in flattened policies to confirm whether the address is matched.

## Getting Started

[Download the ZIP file](https://github.com/joelob99/flatFortiGatePolicy) from the branch and extracts it.
Open flatFortiGatePolicy.html on Firefox, Chrome, or Microsoft Edge(Chromium base), and follows the steps described on the page.

## Flattened Firewall Policy

Flattened Firewall Policy is described in the following format.

```
DOM_NAME,S_INTF,D_INTF,POL_TYPE,POL_ID,POL_NAME,POL_LINE,{accept|deny|ipsec},PROT,S_ADDR,S_PORT,D_ADDR,D_PORT,SD_ADDR,I_TPCD,SA_NEGATE,DA_NEGATE,SV_NEGATE,{enable|disable},LOG,SCHEDULE,COMMENT


  DOM_NAME     domain name
  S_INTF       source interface
  D_INTF       destination interface
  POL_TYPE     policy type
  POL_ID       policy id
  POL_NAME     policy name
  POL_LINE     policy line number
  PROT         protocol service name
  S_ADDR       source network address
  S_PORT       source port service name
  D_ADDR       destination network address
  D_PORT       destination port service name
  SD_ADDR      service destination address
  I_TPCD       icmp-type and icmp-code service name
  SA_NEGATE    true if source address negates
  DA_NEGATE    true if destination address negates
  SV_NEGATE    true if service negates
  LOG          log
  SCHEDULE     schedule name
  COMMENT      comment
```

  - DOM_NAME, S_INTF, D_INTF, POL_ID, POL_NAME, SCHEDULE, and COMMENT are the same as configuration. However, if S_INTF or D_INTF is two or more interfaces, the policy is divided by the interfaces.

  - POL_TYPE is one of the following.

        4to4: IPv4 policy
        6to6: IPv6 policy
        4to6: IPv4 to IPv6 policy
        6to4: IPv6 to IPv4 policy
        4to4m: IPv4 multicast NAT policy
        6to6m: IPv6 multicast NAT policy

  - POL_LINE is the policy order number in policy type.

  - PROT format is the following. If the protocol number is '0', it is changed to 'ip.'

        'NN'

        NN: protocol-number or 'ip'

  - S_PORT and D_PORT format is the following. If PROT is '6'(tcp), '17'(udp), or '132'(sctp) and the port condition is not specified, S_PORT is described as 'eq/any'. If PROT is neither '6', '17', nor '58', S_PORT and D_PORT are described as '-/-'.

        'eq/NN'
        'range/SN-EN'

        NN: port-number or 'any'
        SN: start port-number
        EN: end port-number

  - I_TPCD format is the following. If icmp-type or icmp-code is not specified explicitly, it is described as 'any'. If PROT is not '1'(icmp) and '58'(icmp6), I_TPCD is described as '-/-'.

        'TN/CN'

        TN: icmp-type number or 'any'
        CN: icmp-code number or 'any'

  - S_ADDR and D_ADDR are CIDR representations if the network address is host or subnet address. IPv6 address is adapted to the full represented. If the network address is a range, S_ADDR and D_ADDR are not CIDR representations. Its address is described in start-address, a hyphen, end-address as following.

        IPv4: 'x.x.x.x-y.y.y.y'
        IPv6: 'xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx-yyyy:yyyy:yyyy:yyyy:yyyy:yyyy:yyyy:yyyy'

    Also, if the network address is a wildcard address, its address is described in IPv4 address, a slash, IPv4 wildcard mask, as following.

        IPv4: 'x.x.x.x/m.m.m.m'

    If the network address is FQDN, S_ADDR and D_ADDR are described as FQDN with the prefix is 'fqdn:'. If the network address is geography, S_ADDR and D_ADDR are described as the country name with the prefix is 'geo:'.

    'all' network address is converted as following rules.

        IPv4: '0.0.0.0/0'
        IPv6: '0000:0000:0000:0000:0000:0000:0000:0000/0'

  - SD_ADDR is the CIDR representation if the service destination address is a host address. If the service destination address is a range, it is described in start-address, a hyphen, end-address. Its prefix is 'fqdn:' when FQDN. It is described as '0/0' if the service destination address is '0.0.0.0.' If PROT is neither '6', '17', nor '58', SD_ADDR is described as '-'.

  - LOG is currently not supported. It is described as '-.'

Flattening replaces the objects and group objects of the firewall policies with those values. If a group object has two or more members, the firewall policy is divided by the members. For example, when the object, group object, and policy are defined in the configuration as following, the firewall policy is divided into two entries.

- Configuration:

      config vdom
      edit "VDOM1"
      config firewall address
          edit "OBJ1"
              set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
              set subnet 192.168.0.1 255.255.255.255
          next
          edit "OBJ2"
              set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
              set subnet 10.0.0.1 255.255.255.255
          next
          edit "OBJ3"
              set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
              set subnet 10.1.1.1 255.255.255.255
          next
      end
      config firewall addrgrp
          edit "OGRP1"
              set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
              set member "OBJ2" "OBJ3"
          next
      end
      config firewall policy
          edit "101"
              set uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
              set srcintf "internal1"
              set dstintf "wan2"
              set srcaddr "OBJ1"
              set dstaddr "OGRP1"
              set action accept
              set schedule "always"
              set service "HTTP"
          next
      end
      end

- Flattend Policy:

      VDOM1,internal1,wan2,4to4,101,,1,accept,6,192.168.0.1/32,eq/any,10.0.0.1/32,eq/80,0/0,-/-,false,false,false,enable,-,always,
      VDOM1,internal1,wan2,4to4,101,,1,accept,6,192.168.0.1/32,eq/any,10.1.1.1/32,eq/80,0/0,-/-,false,false,false,enable,-,always,

## Limitation

- IPv4, IPv6, IPv4 to IPv6, and IPv6 to IPv4 policies are supported. Also, IPv4 and IPv6 multicast NAT policies are supported.
- Dynamic and template types in the address object are not supported.
- NAT and VIP are not supported. Therefore, NAT and VIP parameters in policy are not flattened.
- FQDN and geography are not resolved to its IP address when lookup. Therefore, it can not recognize whether FQDN and geography are within the IP segment and the IP range.

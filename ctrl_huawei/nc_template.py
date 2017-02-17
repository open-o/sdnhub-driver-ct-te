#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Copyright 2016-2017 China Telecommunication Co., Ltd.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

__author__ = 'chenhg'

import re

make_cli = lambda x:'<cmd><id>1</id><cmdline>'+x+'</cmdline></cmd>'
ACL_GROUP = 3050
# Get interface index (which will be used by other commands) by its name
#   Args:
#       1. Interface full name
h3c_get_ifindex = '''
    <top xmlns="http://www.h3c.com/netconf/data:1.0" xmlns:h3c="http://www.h3c.com/netconf/base:1.0"  xmlns:reg="http://www.h3c.com/netconf/base:1.0">
        <Ifmgr>
          <Interfaces>
            <Interface>
              <IfIndex></IfIndex>
              <Name>%s</Name>
            </Interface>
          </Interfaces>
        </Ifmgr>
    </top>

'''
h3c_get_ifindex_reply_pat = {'IfIndex': re.compile(r'<IfIndex>(\d+)</IfIndex>')}

h3c_merge_config_hdr = '''    <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
       <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
'''
h3c_del_config_hdr = '''    <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
       <top web:operation="delete" xmlns="http://www.h3c.com/netconf/config:1.0">
'''
h3c_edit_config_footer = '''
       </top>
    </nc:config>
'''
# Add static route table
#   Args:
#       1. Target IP subnet
#       2. Netmask length (0~32)
#       3. Next hop IP
h3c_static_route = '''
    <config>
        <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
            <StaticRoute>
               <Ipv4StaticRouteConfigurations>
                  <RouteEntry>
                     <DestVrfIndex>0</DestVrfIndex>
                        <DestTopologyIndex>0</DestTopologyIndex>
                        <Ipv4Address>%s</Ipv4Address>
                        <Ipv4PrefixLength>%s</Ipv4PrefixLength>
                        <NexthopVrfIndex>0</NexthopVrfIndex>
                        <NexthopIpv4Address>%s</NexthopIpv4Address>
                        <IfIndex>0</IfIndex>
                  </RouteEntry>
               </Ipv4StaticRouteConfigurations>
            </StaticRoute>

       </top>
    </config>

'''

# Limit speed of an Interface
#   Args:
#       1. Interface Index
#       2. Direction: 0--Outbound  1--Inbound
#       3. Average bandwidth, in Kbps
#       4. Peak bandwidth, in Kbps
h3c_car_limit_base = '''
            <CAR>
              <CarPolicies>
                <Policy>
                  <IfIndex>%s</IfIndex>
                  <Direction>%s</Direction>
                  <Type>4</Type>
                  <Value>0</Value>
                  <CIR>%s</CIR>
                  <PIR>%s</PIR>
               </Policy>
              </CarPolicies>
            </CAR>
'''
h3c_car_limit = h3c_merge_config_hdr + h3c_car_limit_base + h3c_edit_config_footer

# Apply an ACL to an Interface.
#   Args:
#       1. Interface Index
#       2. Direction: 2--Outbound  1--Inbound
#       3. ACL number
h3c_acl_base = '''
            <ACL>
              <PfilterApply>
                <Pfilter>
                  <AppObjType>1</AppObjType>
                  <AppObjIndex>%s</AppObjIndex>
                  <AppDirection>%s</AppDirection>
                  <AppAclType>1</AppAclType>
                  <AppAclGroup>%s</AppAclGroup>
                </Pfilter>
              </PfilterApply>
            </ACL>
'''
h3c_acl = h3c_merge_config_hdr + h3c_acl_base + h3c_edit_config_footer

# Create an ACL group
#   Args:
#       1. ACL group number 3000~3999
h3c_acl_group_base ='''
            <ACL>
              <NamedGroups>
                <Group>
                  <GroupType>1</GroupType>
                  <GroupCategory>2</GroupCategory>
                  <GroupIndex>%s</GroupIndex>
                </Group>
              </NamedGroups>
            </ACL>
'''
h3c_acl_group = h3c_merge_config_hdr + h3c_acl_group_base + h3c_edit_config_footer

# Create an ACL rule
#   Args:
#       0. ACL Group Number
#       1. ACL rule number
#       2. Action 1--Deny, 2-Allow
#       3~4. IP and Mask

h3c_acl_rule_out_base = '''
        <ACL>
          <IPv4NamedAdvanceRules>
            <Rule>
              <GroupIndex>%s</GroupIndex>
              <RuleID>%s</RuleID>
              <Action>%s</Action>
              <ProtocolType>256</ProtocolType>
              <SrcAny>true</SrcAny>
              <SrcIPv4>
                <SrcIPv4Addr></SrcIPv4Addr>
                <SrcIPv4Wildcard></SrcIPv4Wildcard>
              </SrcIPv4>
              <DstAny>false</DstAny>
              <DstIPv4>
                <DstIPv4Addr>%s</DstIPv4Addr>
                <DstIPv4Wildcard>%s</DstIPv4Wildcard>
              </DstIPv4>
            </Rule>
          </IPv4NamedAdvanceRules>
        </ACL>
'''

h3c_acl_rule_in_base = '''
        <ACL>
          <IPv4NamedAdvanceRules>
            <Rule>
              <GroupIndex>%s</GroupIndex>
              <RuleID>%s</RuleID>
              <Action>%s</Action>
              <ProtocolType>255</ProtocolType>
              <SrcAny>false</SrcAny>
              <SrcIPv4>
                <SrcIPv4Addr>%s</SrcIPv4Addr>
                <SrcIPv4Wildcard>%s</SrcIPv4Wildcard>
              </SrcIPv4>
              <DstAny>true</DstAny>
              <DstIPv4>
                <DstIPv4Addr></DstIPv4Addr>
                <DstIPv4Wildcard></DstIPv4Wildcard>
              </DstIPv4>
            </Rule>
          </IPv4NamedAdvanceRules>
        </ACL>
'''

h3c_acl_rule_del_base = '''
        <ACL>
          <IPv4NamedAdvanceRules>
            <Rule>
              <GroupIndex>%s</GroupIndex>
              <RuleID>%s</RuleID>
            </Rule>
          </IPv4NamedAdvanceRules>
        </ACL>
'''
h3c_acl_rule_out = h3c_merge_config_hdr + h3c_acl_rule_out_base + h3c_edit_config_footer
h3c_acl_rule_in = h3c_merge_config_hdr + h3c_acl_rule_in_base + h3c_edit_config_footer
h3c_acl_rule_del = h3c_del_config_hdr + h3c_acl_rule_del_base + h3c_edit_config_footer


# Create NAT 1:1 mapping. (Maybe you should create an appropriate ACL before call this config)
#   Args:
#       1. Local IP (start)
#       2. Local IP (end)
#       3. Global IP
#       4. Global IP mask bits (32 means a unique IP)

#                     <ACLNumber>%s</ACLNumber>

h3c_nat_map_base = '''
        <NAT>
          <OutboundStaticMappings>
            <Mapping>
              <LocalInfo>
                <LocalVRF></LocalVRF>
                <StartIpv4Address>%s</StartIpv4Address>
                <EndIpv4Address>%s</EndIpv4Address>
              </LocalInfo>
              <GlobalInfo>
                <GlobalVRF></GlobalVRF>
                <Ipv4Address>%s</Ipv4Address>
                <Ipv4PrefixLength>%s</Ipv4PrefixLength>
              </GlobalInfo>
              <Reversible>%s</Reversible>
            </Mapping>
          </OutboundStaticMappings>
        </NAT>
'''

h3c_nat_map_base2 = '''
        <NAT>
          <OutboundStaticMappings>
            <Mapping>
              <LocalInfo>
                <LocalVRF></LocalVRF>
                <StartIpv4Address>%s</StartIpv4Address>
              </LocalInfo>
              <Reversible>%s</Reversible>
            </Mapping>
          </OutboundStaticMappings>
        </NAT>
'''

h3c_nat_map_base_3 = '''
    <Configuration>
        undo nat static outbound %s
    </Configuration>

'''
h3c_nat_map = h3c_merge_config_hdr + h3c_nat_map_base + h3c_edit_config_footer
h3c_nat_map_del = h3c_del_config_hdr + h3c_nat_map_base2 + h3c_edit_config_footer
h3c_nat_map_del2 =  h3c_nat_map_base_3

h3c_get_nat = '''
    <top xmlns="http://www.h3c.com/netconf/data:1.0" xmlns:h3c="http://www.h3c.com/netconf/base:1.0"  xmlns:reg="http://www.h3c.com/netconf/base:1.0">
        <NAT>
          <OutboundStaticMappings>
            <Mapping>
              <LocalInfo>
                <LocalVRF></LocalVRF>
                <StartIpv4Address></StartIpv4Address>
                <EndIpv4Address></EndIpv4Address>
              </LocalInfo>
              <GlobalInfo>
                <GlobalVRF></GlobalVRF>
                <Ipv4Address>%s</Ipv4Address>
                <Ipv4PrefixLength>%s</Ipv4PrefixLength>
              </GlobalInfo>
              <Reversible>false</Reversible>
            </Mapping>
          </OutboundStaticMappings>
        </NAT>
    </top>

'''
# h3c_get_nat_reply_pat = {'Ipv4Address': re.compile(r'<Ipv4Address>(.+?)</Ipv4Address>'),
#                          'Ipv4PrefixLength': re.compile(r'<Ipv4PrefixLength>(.+?)</Ipv4PrefixLength>')}
h3c_get_nat_reply_pat = {'StartIpv4Address': re.compile(r'<StartIpv4Address>(.+?)</StartIpv4Address>')}
# Edit SubInterface for an interface
# Args:
#  1. Parent Ifindex  (For delete, it is subif index.)
#  2. SubInterfaceNumber

h3c_sub_add_if = '''
    <top  xmlns="http://www.h3c.com/netconf/action:1.0">
        <Ifmgr>
          <SubInterfaces>
            <Interface>
              <IfIndex>%s</IfIndex>
              <SubNum>%s</SubNum>
            </Interface>
          </SubInterfaces>
        </Ifmgr>
    </top>
'''

# h3c_sub_add_if2 = '''
#     <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
#     <top web:operation="merge" xmlns="http://www.h3c.com/netconf/action:1.0">
#             <Ifmgr>
#               <NewSubInterfaces>
#                 <Interface>
#                   <IfIndex>%s</IfIndex>
#                   <SubNum>%s</SubNum>
#                 </Interface>
#               </NewSubInterfaces>
#             </Ifmgr>
#     </top>
#     </nc:config>
#
# '''

h3c_sub_rm_if = '''
    <top  xmlns="http://www.h3c.com/netconf/action:1.0">
        <Ifmgr>
          <SubInterfaces>
            <Interface>
              <IfIndex>%s</IfIndex>
              <Remove></Remove>
            </Interface>
          </SubInterfaces>
        </Ifmgr>
    </top>
'''

# Set IP to interface
# Args:
#  1. index of interface or sub-interface
#  2. ip str
#  3. subnet mask
#

h3c_set_ip = '''
    <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
        <IPV4ADDRESS>
          <Ipv4Addresses>
            <Ipv4Address>
              <IfIndex>%s</IfIndex>
              <Ipv4Address>%s</Ipv4Address>
              <Ipv4Mask>%s</Ipv4Mask>
              <AddressOrigin>1</AddressOrigin>
            </Ipv4Address>
          </Ipv4Addresses>
        </IPV4ADDRESS>
    </top>
    </nc:config>
'''
# Create PBR Node:
#  addressType: 0--IPv4, Mode: 2--Deny
# Args:
#   1. Policy  name
#   2. Policy number
#   3. ACL Number.

h3c_pbr_node = '''
    <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
        <PBR>
          <PBRPolicyNode>
            <PolicyNode>
              <AddressType>0</AddressType>
              <PolicyName>%s</PolicyName>
              <NodeID>%s</NodeID>
              <Mode>2</Mode>
              <ACLNumber>%s</ACLNumber>
              <!-- <ACLName></ACLName> -->
              <!--
              <MatchVxlanID></MatchVxlanID>
              <MatchPacketLenMin>1</MatchPacketLenMin>
              <MatchPacketLenMax>65535</MatchPacketLenMax>
              <ApplyPrecedence>2</ApplyPrecedence>
              <ApplyIPDF>1</ApplyIPDF>
              <ApplyContinue>false</ApplyContinue> -->

            </PolicyNode>
          </PBRPolicyNode>
        </PBR>
    </top>
    </nc:config>
'''

# An 'apply' command of the created PBR node.
# Args:
#   1. Policy name
#   2. Policy Node number
#   3. next hop IP address

h3c_pbr_nexthop = '''
    <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
        <PBR>
          <PBRApplyNexthop>
            <ApplyNexthop>
              <AddressType>0</AddressType>
              <PolicyName>%s</PolicyName>
              <NodeID>%s</NodeID>
              <Mode>0</Mode>
              <VrfIndex>0</VrfIndex>
              <IpAddress>%s</IpAddress>
              <!-- <TrackID></TrackID> -->
              <NexthopDirect>false</NexthopDirect>
            </ApplyNexthop>
          </PBRApplyNexthop>
        </PBR>
    </top>
    </nc:config>
'''

# Apply policy to interface:
# Args:
#
#   1. Policy Name
#   2. PBR Node number
#   3. Interface index
h3c_pbr_apply_if = '''
    <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
        <PBR>
          <PBRApplyOutInterface>
            <ApplyOutInterface>
              <AddressType>0</AddressType>
              <PolicyName>%s</PolicyName>
              <NodeID>%s</NodeID>
              <Mode>0</Mode>
              <IfIndex>%s</IfIndex>
              <TrackID></TrackID>
            </ApplyOutInterface>
          </PBRApplyOutInterface>
        </PBR>
    </top>
    </nc:config>
'''

# Apply policy to interface:
# Args:
#
#   1. Policy Name
#   3. Interface index
h3c_pbr_apply_if2 = '''
    <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:web="urn:ietf:params:xml:ns:netconf:base:1.0">
    <top web:operation="merge" xmlns="http://www.h3c.com/netconf/config:1.0">
        <PBR>
          <PBRIfPolicy>
             <IfPolicy>
               <AddressType>0</AddressType>
               <PolicyName>%s</PolicyName>
               <IfIndex>%s</IfIndex>
             </IfPolicy>
          </PBRIfPolicy>
        </PBR>
    </top>
    </nc:config>
'''


h3c_if_caps = '''
    <top xmlns="http://www.h3c.com/netconf/data:1.0" xmlns:h3c="http://www.h3c.com/netconf/base:1.0"  xmlns:reg="http://www.h3c.com/netconf/base:1.0">
        <Ifmgr>
          <InterfaceCapabilities>
            <Interface>
              <IfIndex>%s</IfIndex>
              <Configurable></Configurable>
              <Shutdown></Shutdown>
              <Speed></Speed>
              <AutoSpeed></AutoSpeed>
              <Duplex></Duplex>
              <PortLayer></PortLayer>
              <Loopback></Loopback>
              <MDI></MDI>
              <Bandwidth></Bandwidth>
              <MinMTU></MinMTU>
              <MaxMTU></MaxMTU>
              <MinSubNum></MinSubNum>
              <MaxSubNum></MaxSubNum>
              <MaxCreateSubNum></MaxCreateSubNum>
              <ContextAllocType></ContextAllocType>
              <Removable></Removable>
              <Interval></Interval>
              <ForceUP></ForceUP>
              <LoopbackAutoStop></LoopbackAutoStop>
            </Interface>
          </InterfaceCapabilities>
        </Ifmgr>
    </top>
'''

h3c_if_status = '''true
    <top xmlns="http://www.h3c.com/netconf/data:1.0" xmlns:h3c="http://www.h3c.com/netconf/base:1.0"  xmlns:reg="http://www.h3c.com/netconf/base:1.0">
        <Ifmgr>
          <Interfaces>
            <Interface>
              <IfIndex>%s</IfIndex>
              <Name></Name>
              <AbbreviatedName></AbbreviatedName>
              <PortIndex></PortIndex>
              <ifTypeExt></ifTypeExt>
              <ifType></ifType>
              <Description></Description>
              <AdminStatus></AdminStatus>
              <OperStatus></OperStatus>
              <ConfigSpeed></ConfigSpeed>
              <ActualSpeed></ActualSpeed>
              <ConfigDuplex></ConfigDuplex>
              <ActualDuplex></ActualDuplex>
              <PortLayer></PortLayer>
              <LinkType></LinkType>
              <PVID></PVID>
              <InetAddressIPV4></InetAddressIPV4>
              <InetAddressIPV4Mask></InetAddressIPV4Mask>
              <PhysicalIndex></PhysicalIndex>
              <MAC></MAC>
              <ForwardingAttributes></ForwardingAttributes>
              <Loopback></Loopback>
              <MDI></MDI>
              <ConfigMTU></ConfigMTU>
              <ActualMTU></ActualMTU>
              <ConfigBandwidth></ConfigBandwidth>
              <ActualBandwidth></ActualBandwidth>
              <SubPort></SubPort>
              <Interval></Interval>
              <ForceUP></ForceUP>
              <KeepAlive></KeepAlive>
              <KeepAliveRetry></KeepAliveRetry>
              <DefaultMac></DefaultMac>
              <LastChange></LastChange>
            <PhyLastChange></PhyLastChange>
            </Interface>
          </Interfaces>
        </Ifmgr>
    </top>
'''


#1.创建显示路径主路径名称
# explicit-path a-b-pri      //主显示路径
# Args:
#   1. primary explicit path Name
hw_create_primary_path_name = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <explicitPaths>
            <explicitPath operation="create">
              <explicitPathName>%s</explicitPathName>
            </explicitPath>
          </explicitPaths>
        </mplsTe>
      </mpls>
    </config>
'''

#3.创建主路径每一跳
# next hop 10.1.12.1
# next hop 10.1.12.2
hw_create_primary_path_hop_detail = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <explicitPaths>
            <explicitPath>
              <explicitPathName>tunnel_primary</explicitPathName>
              <explicitPathHops>
                <explicitPathHop operation="create">
                  <mplsTunnelHopIndex>1</mplsTunnelHopIndex>
                  <mplsTunnelHopIpAddr>10.230.10.9</mplsTunnelHopIpAddr>
                  <mplsTunnelHopType>includeStrict</mplsTunnelHopType>
                  <mplsTunnelHopIntType>default</mplsTunnelHopIntType>
                  <mplsTunnelHopAddrType>IPV4</mplsTunnelHopAddrType>
                </explicitPathHop>
                <explicitPathHop operation="create">
                  <mplsTunnelHopIndex>2</mplsTunnelHopIndex>
                  <mplsTunnelHopIpAddr>10.230.10.1</mplsTunnelHopIpAddr>
                  <mplsTunnelHopType>includeStrict</mplsTunnelHopType>
                  <mplsTunnelHopIntType>default</mplsTunnelHopIntType>
                  <mplsTunnelHopAddrType>IPV4</mplsTunnelHopAddrType>
                </explicitPathHop>
              </explicitPathHops>
            </explicitPath>
          </explicitPaths>
        </mplsTe>
      </mpls>
    </config>
'''

#3.创建主路径每一跳
# next hop 10.1.12.1
# next hop 10.1.12.2
# Args:
#   1. primary explicit path Name
#   2. primary path hop items string
hw_create_primary_path_hop_container = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <explicitPaths>
            <explicitPath>
              <explicitPathName>%s</explicitPathName>
              <explicitPathHops>%s</explicitPathHops>
            </explicitPath>
          </explicitPaths>
        </mplsTe>
      </mpls>
    </config>
'''
# Args:
#   1. mplsTunnelHopIndex
#   2. mplsTunnelHopIpAddr
hw_create_primary_path_hop_item = '''
    <explicitPathHop operation="create">
      <mplsTunnelHopIndex>%s</mplsTunnelHopIndex>
      <mplsTunnelHopIpAddr>%s</mplsTunnelHopIpAddr>
      <mplsTunnelHopType>includeStrict</mplsTunnelHopType>
      <mplsTunnelHopIntType>default</mplsTunnelHopIntType>
      <mplsTunnelHopAddrType>IPV4</mplsTunnelHopAddrType>
    </explicitPathHop>
'''


# '5.创建RSVP-TE隧道名称'
'''
cli
[41:42.560][~BJ-YJY-TEST.R1-NE5000E]interface Tunnel 1
[42:11.116][*BJ-YJY-TEST.R1-NE5000E-Tunnel1]tunnel-protocol mpls te
[42:28.526][*BJ-YJY-TEST.R1-NE5000E-Tunnel1]destination 3.3.3.3
[43:11.190][*BJ-YJY-TEST.R1-NE5000E-Tunnel1]mpls te record-route label
[49:15.686][~BJ-YJY-TEST.R1-NE5000E-Tunnel1]mpls te tunnel-id 1
'''
# Args:
#   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
#   2. mplsTunnelEgressLSRId
#   3. mplsTunnelIndex
#   4. mplsTeTunnelSetupPriority
#   5. holdPriority
#   6. mplsTunnelBandwidth (100Kbps)
#   7. includeAny (0x1)
#   8. excludeAny (0x2)
# <hotStandyEnable>%s</hotStandbyEnable >
hw_create_tunnel = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <rsvpTeTunnels>
            <rsvpTeTunnel operation="create">
              <tunnelName>%s</tunnelName>
              <mplsTunnelEgressLSRId>%s</mplsTunnelEgressLSRId>
              <mplsTunnelIndex>%s</mplsTunnelIndex>
              <mplsTeTunnelSetupPriority>%s</mplsTeTunnelSetupPriority>
              <holdPriority>%s</holdPriority>
              <mplsTunnelBandwidth>%s</mplsTunnelBandwidth>
              <mplsTunnelRecordRoute>RECORD_ROUTE_ONLY</mplsTunnelRecordRoute>
              <tunnelPaths>
                <tunnelPath operation="merge">
                  <pathType>primary</pathType>
                  <includeAny>%s</includeAny>
                  <excludeAny>%s</excludeAny>
                </tunnelPath>
              </tunnelPaths>
            </rsvpTeTunnel>
          </rsvpTeTunnels>
        </mplsTe>
      </mpls>
    </config>
'''

# Args:
#   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
#   2. mplsTunnelEgressLSRId
#   3. mplsTunnelIndex
#   4. mplsTeTunnelSetupPriority
#   5. holdPriority
#   6. mplsTunnelBandwidth (100Kbps)
#   7. explicitPathName
hw_create_tunnel_with_hops = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <rsvpTeTunnels>
            <rsvpTeTunnel operation="create">
              <tunnelName>%s</tunnelName>
              <mplsTunnelEgressLSRId>%s</mplsTunnelEgressLSRId>
              <mplsTunnelIndex>%s</mplsTunnelIndex>
              <mplsTeTunnelSetupPriority>%s</mplsTeTunnelSetupPriority>
              <holdPriority>%s</holdPriority>
              <mplsTunnelBandwidth>%s</mplsTunnelBandwidth>
              <mplsTunnelRecordRoute>RECORD_ROUTE_ONLY</mplsTunnelRecordRoute>
              <tunnelPaths>
                <tunnelPath operation="create">
                  <pathType>primary</pathType>
                  <explicitPathName>%s</explicitPathName>
                </tunnelPath>
              </tunnelPaths>
            </rsvpTeTunnel>
          </rsvpTeTunnels>
        </mplsTe>
      </mpls>
    </config>
'''

# 6.RSVP-TE隧道路径配置
# Args:
#   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
#   2. explicitPathName
hw_tunnel_config = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <rsvpTeTunnels>
            <rsvpTeTunnel operation="merge">
              <tunnelName>%s</tunnelName>
              <tunnelPaths>
                <tunnelPath operation="create">
                  <pathType>primary</pathType>
                  <explicitPathName>%s</explicitPathName>
                </tunnelPath>
              </tunnelPaths>
            </rsvpTeTunnel>
          </rsvpTeTunnels>
        </mplsTe>
      </mpls>
    </config>
'''

# 隧道的IGP属性配置
# mpls te igp shortcut isis  #配置IGP Shortcut
# mpls te igp metric absolute 5 #配置TE隧道的IGP度量
# Args:
#   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
hw_tunnel_igp_config = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <rsvpTeTunnels>
            <rsvpTeTunnel>
              <tunnelName>%s</tunnelName>
              <tunnelInterface>
                <igpAttr operation="create">
                  <advertiseEnable>false</advertiseEnable>
                  <advertiseIpv6Enable>false</advertiseIpv6Enable>
                  <shortcutType>isis</shortcutType>
                  <igpMetricType>absolute</igpMetricType>
                  <absoluteIgpMetricValue>5</absoluteIgpMetricValue>
                </igpAttr>
              </tunnelInterface>
            </rsvpTeTunnel>
          </rsvpTeTunnels>
        </mplsTe>
      </mpls>
    </config>
'''

# ISIS使能配置
# isis enable 100 #使能隧道接口的IS-IS进程
# Args:
#   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
hw_tunnel_isis_config = '''
    <config>
      <isiscomm xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <isSites>
          <isSite operation="merge">
            <instanceId>100</instanceId>
            <isCircuits>
              <isCircuit operation="merge">
                <ifName>%s</ifName>
                <ipv4Enable>true</ipv4Enable>
                <ipv6Enable>false</ipv6Enable>
              </isCircuit>
            </isCircuits>
          </isSite>
        </isSites>
      </isiscomm>
    </config>
'''

# 配置主地址
# ip address unnumbered interface LoopBack0 #配置路由发布
# Args:
#   1. ifName,eg:Tunnel5(Tunnel prefix is necessary)
hw_tunnel_mainIpAddr_config = '''
    <config>
      <ifm xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <interfaces>
          <interface operation="merge">
            <ifName>%s</ifName>
            <ifmAm4>
              <unNumIfName>LoopBack0</unNumIfName>
              <addrCfgType>unnumbered</addrCfgType>
            </ifmAm4>
          </interface>
        </interfaces>
      </ifm>
    </config>
'''

# Tunnel下开启计数
# statistic enable
# Args:
#   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
hw_tunnel_statistic_enable = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <rsvpTeTunnels>
            <rsvpTeTunnel>
              <tunnelName>%s</tunnelName>
              <tunnelInterface operation="merge">
                <statEnable>true</statEnable>
              </tunnelInterface>
            </rsvpTeTunnel>
          </rsvpTeTunnels>
        </mplsTe>
      </mpls>
    </config>
'''


#[58:37.307][~BJ-YJY-TEST.R1-NE5000E]acl number 3050
# Args:
#   1. aclNumOrName 3050
hw_add_acl = '''
    <config>
      <acl xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <aclGroups>
          <aclGroup operation="create">
            <aclNumOrName>%s</aclNumOrName>
            <aclDescription>flow_acl</aclDescription>
          </aclGroup>
        </aclGroups>
      </acl>
    </config>
'''

# [59:24.920][*BJ-YJY-TEST.R1-NE5000E-acl4-advance-3050]rule 5 permit ip source 10.0.1.10 0
# Args:
#   1. aclNumOrName 3050
#   2. aclRuleID 5
#   3. aclAction permit
#   4. aclSourceIp 10.0.1.10
#   5. aclSrcWild 0.0.0.255
#   6. aclDestIp 10.0.1.10
#   7. aclDestWild 0.0.0.255
hw_add_rule = '''
    <config>
      <acl xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <aclGroups>
          <aclGroup operation="merge">
            <aclNumOrName>%s</aclNumOrName>
            <aclRuleAdv4s>
              <aclRuleAdv4 operation="create">
                <aclRuleName>%s</aclRuleName>
                <aclRuleID>%s</aclRuleID>
                <aclAction>%s</aclAction>
                <aclProtocol>0</aclProtocol>
                <aclSourceIp>%s</aclSourceIp>
                <aclSrcWild>%s</aclSrcWild>
                <aclDestIp>%s</aclDestIp>
                <aclDestWild>%s</aclDestWild>
              </aclRuleAdv4>
            </aclRuleAdv4s>
          </aclGroup>
        </aclGroups>
      </acl>
    </config>
'''
# [00:35.719][~BJ-YJY-TEST.R1-NE5000E]traffic classifier flow11to1
# <!--配置class模板 -->
# Args:
#   1. classifierName flow11to3
hw_add_classifier = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosCbQos>
            <qosClassifiers>
                <qosClassifier operation="create">
                    <classifierName>%s</classifierName>
                    <description></description>
                    <operator>or</operator>
                </qosClassifier>
            </qosClassifiers>
        </qosCbQos>
      </qos>
    </config>
'''
# [00:49.211][*BJ-YJY-TEST.R1-NE5000E-classifier-flow]if-match acl 3050
# Args:
#   1. classifierName flow11to3
#   2. aclName 3050
hw_classifier_match_rule = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosCbQos>
          <qosClassifiers>
            <qosClassifier operation="merge">
                <classifierName>%s</classifierName>
                <operator>or</operator>
                <qosRuleAcls>
                    <qosRuleAcl operation="create">
                        <aclName>%s</aclName>
                    </qosRuleAcl>
                </qosRuleAcls>
            </qosClassifier>
          </qosClassifiers>
        </qosCbQos>
      </qos>
    </config>
'''
# [02:01.918][~BJ-YJY-TEST.R1-NE5000E]traffic behavior flow_redirect
# <!--配置behavior模板-->
# Args:
#   1. behaviorName flow_redirect
hw_add_behavior = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosCbQos>
          <qosBehaviors>
            <qosBehavior operation="create">
                <behaviorName>%s</behaviorName>
                <description></description>
            </qosBehavior>
          </qosBehaviors>
        </qosCbQos>
      </qos>
    </config>
'''

#  redirect ip-nexthop 3.3.3.3
# [02:12.900][*BJ-YJY-TEST.R1-NE5000E-behavior-flow_redirect]redirect interface Tunnel 1
# Args:
#   1. behaviorName flow_redirect
#   2. nextHop 3.3.3.3
hw_add_behavior_action = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosCbQos>
          <qosBehaviors>
            <qosBehavior operation="merge">
              <behaviorName>%s</behaviorName>
              <qosActRdrNhps>
                <qosActRdrNhp operation="create">
                  <rdrType>backup</rdrType>
                  <nextHop>%s</nextHop>
                  <filterDefault>false</filterDefault>
                  <filterBlackhole>false</filterBlackhole>
                  <drop>false</drop>
                </qosActRdrNhp>
              </qosActRdrNhps>
            </qosBehavior>
          </qosBehaviors>
        </qosCbQos>
      </qos>
    </config>
'''
# [04:59.887][~BJ-YJY-TEST.R1-NE5000E]traffic policy flow_policy
# <!--配置policy模板-->
# Args:
#   1. policyName flow_policy
hw_add_policy = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosCbQos>
          <qosPolicys>
            <qosPolicy operation="create">
                <policyName>%s</policyName>
                <description></description>
            </qosPolicy>
          </qosPolicys>
        </qosCbQos>
      </qos>
    </config>
'''
# [05:22.517][*BJ-YJY-TEST.R1-NE5000E-trafficpolicy-flow_policy]classifier flow11to1 behavior flow_redirect
# <!--配置policy模板下CB对-->
# Args:
#   1. policyName flow_policy
#   2. classifierName flow11to3
#   3. behaviorName flow_redirect
hw_add_policy_action = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosCbQos>
          <qosPolicys>
            <qosPolicy operation="merge">
                <policyName>%s</policyName>
                <qosPolicyNodes>
                    <qosPolicyNode operation="create">
                        <classifierName>%s</classifierName>
                        <behaviorName>%s</behaviorName>
                        <priority></priority>
                    </qosPolicyNode>
                </qosPolicyNodes>
            </qosPolicy>
          </qosPolicys>
        </qosCbQos>
      </qos>
    </config>
'''
# [07:48.908][~BJ-YJY-TEST.R1-NE5000E]interface GigabitEthernet1/0/20
# [08:07.983][~BJ-YJY-TEST.R1-NE5000E-GigabitEthernet1/0/20]traffic-policy flow_policy inbound
# <!—将QoS策略下发到接口-->
# Args:
#   1. ifName GigabitEthernet1/0/22
#   2. policyName flow_policy
hw_apply_policy_to_interface = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosIfQoss>
          <qosIfQos operation="merge">
            <ifName>%s</ifName>
            <qosPolicyApplys>
                <qosPolicyApply operation="create">
                    <direction>inbound</direction>
                    <policyName>%s</policyName>
                    <layer>none</layer>
                    <identifier>no</identifier>
                    <vlanMode>false</vlanMode>
                    <groupId>0</groupId>
                </qosPolicyApply>
            </qosPolicyApplys>
          </qosIfQos>
        </qosIfQoss>
      </qos>
    </config>
'''

#创接口IP
# interface LoopBack1
#  ip address 3.3.3.4 255.255.255.255
# Args:
#   1. ifName LoopBack1
#   2. ifIpAddr 3.3.3.4
#   3. subnetMask 255.255.255.255
hw_create_intf_ip = '''
    <config>
      <ifm xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <interfaces>
          <interface operation="merge">
            <ifName>%s</ifName>
            <ifmAm4>
                <am4CfgAddrs>
                    <am4CfgAddr operation="create">
                        <ifIpAddr>%s</ifIpAddr>
                        <subnetMask>%s</subnetMask>
                        <addrType>main</addrType>
                    </am4CfgAddr>
                </am4CfgAddrs>
            </ifmAm4>
          </interface>
        </interfaces>
      </ifm>
    </config>


'''

#静态路由NetConf接口：<ifName>NULL0</ifName> 是填写Tunnel name
# ip route-static 3.3.3.4 255.255.255.255 Tunnel6
# Args:
#   1. prefix 3.3.3.4
#   2. maskLength 32
#   2. ifName Tunnel6
hw_route_static_config = '''
    <config>
      <staticrt xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <staticrtbase>
          <srRoutes>
            <srRoute operation="create">
              <vrfName>_public_</vrfName>
              <afType>ipv4unicast</afType>
              <topologyName>base</topologyName>
              <prefix>%s</prefix>
              <maskLength>%s</maskLength>
              <ifName>%s</ifName>
              <destVrfName>_public_</destVrfName>
              <nexthop>0.0.0.0</nexthop>
              <description/>
              <preference/>
              <tag/>
              <bfdEnable>false</bfdEnable>
              <sessionName/>
              <trackNqaAdminName/>
              <trackNqaTestName/>
              <isInheritCost>false</isInheritCost>
              <isPermanent>false</isPermanent>
              <isNoAdvertise>false</isNoAdvertise>
              <trackEfmIfName>Invalid0</trackEfmIfName>
              <isRelayHostRoute>false</isRelayHostRoute>
            </srRoute>
          </srRoutes>
        </staticrtbase>
      </staticrt>
    </config>

'''

# 链路上管理组属性配置: 接口GigabitEthernet1/0/0下配置mpls te link administrative group 1
# Args:
#   1. ifName GigabitEthernet1/0/0
#   2. adminGroups 0x2
hw_link_property_config = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <teLinks>
            <teLink operation="merge">
              <interfaceName>%s</interfaceName>
              <adminGroups>%s</adminGroups>
            </teLink>
          </teLinks>
        </mplsTe>
      </mpls>
    </config>
'''

# undo mpls te link administrative group
hw_del_link_property_config = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <teLinks>
            <teLink operation="delete">
              <interfaceName>%s</interfaceName>
              <adminGroups>%s</adminGroups>
            </teLink>
          </teLinks>
        </mplsTe>
      </mpls>
    </config>
'''

# delete tunnel
# undo interface Tunnel 311
# undo explicit-path primary_Tunnel311
# Args:
#   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
hw_del_tunnel = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <rsvpTeTunnels>
            <rsvpTeTunnel operation="delete">
              <tunnelName>%s</tunnelName>
            </rsvpTeTunnel>
          </rsvpTeTunnels>
        </mplsTe>
      </mpls>
    </config>
'''
# Args:
#   1. explicitPathName
hw_del_primary_path_name = '''
    <config>
      <mpls xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <mplsTe>
          <explicitPaths>
            <explicitPath operation="delete">
              <explicitPathName>%s</explicitPathName>
            </explicitPath>
          </explicitPaths>
        </mplsTe>
      </mpls>
    </config>
'''

#delete added flow
# to_router:
# undo interface LoopBack1
# from_router:
# [15:58.677]interface GigabitEthernet1/0/4
# [16:05.724][~BJ-YJY-TEST.R3-NE5000E-GigabitEthernet1/0/4]undo traffic-policy inbound
# [16:08.209][*BJ-YJY-TEST.R3-NE5000E-GigabitEthernet1/0/4]commit
# undo traffic policy policy_Tunnel113
# undo traffic behavior behavior_Tunnel113
# undo traffic classifier cls_Tunnel113
# undo acl 3050
# undo ip route-static 11.11.11.29 255.255.255.255 Tunnel113

# Args:
#   1. ifName LoopBack1
hw_del_intf_ip = '''
    <config>
      <ifm xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <interfaces>
          <interface operation="delete">
            <ifName>%s</ifName>
          </interface>
        </interfaces>
      </ifm>
    </config>
'''
# Args:
#   1. ifName GigabitEthernet1/0/22
#   2. policyName flow_policy
hw_undo_policy_to_interface = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosIfQoss>
          <qosIfQos>
            <ifName>%s</ifName>
            <qosPolicyApplys>
                <qosPolicyApply operation="delete">
                    <direction>inbound</direction>
                    <policyName>%s</policyName>
                    <layer>none</layer>
                    <vlanMode>false</vlanMode>
                    <groupId>0</groupId>
                </qosPolicyApply>
            </qosPolicyApplys>
          </qosIfQos>
        </qosIfQoss>
      </qos>
    </config>
'''
# Args:
#   1. policyName flow_policy
hw_del_policy = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosCbQos>
          <qosPolicys>
            <qosPolicy operation="delete">
                <policyName>%s</policyName>
            </qosPolicy>
          </qosPolicys>
        </qosCbQos>
      </qos>
    </config>
'''
# Args:
#   1. behaviorName flow_redirect
hw_del_behavior = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosCbQos>
          <qosBehaviors>
            <qosBehavior operation="delete">
                <behaviorName>%s</behaviorName>
            </qosBehavior>
          </qosBehaviors>
        </qosCbQos>
      </qos>
    </config>
'''
# Args:
#   1. classifierName flow11to3
hw_del_classifier = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosCbQos>
          <qosClassifiers>
            <qosClassifier operation="delete">
                <classifierName>%s</classifierName>
                <operator>or</operator>
            </qosClassifier>
          </qosClassifiers>
        </qosCbQos>
      </qos>
    </config>
'''

# Args:
#   1. policyName flow_policy
#   2. behaviorName flow_redirect
#   3. classifierName flow11to3
hw_del_pol_beh_cls = '''
    <config>
      <qos xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <qosCbQos>
          <qosPolicys>
            <qosPolicy operation="delete">
                <policyName>%s</policyName>
            </qosPolicy>
          </qosPolicys>
          <qosBehaviors>
            <qosBehavior operation="delete">
                <behaviorName>%s</behaviorName>
            </qosBehavior>
          </qosBehaviors>
          <qosClassifiers>
            <qosClassifier operation="delete">
                <classifierName>%s</classifierName>
                <operator>or</operator>
            </qosClassifier>
          </qosClassifiers>
        </qosCbQos>
      </qos>
    </config>
'''
# Args:
#   1. aclNumOrName 3050
hw_del_acl = '''
    <config>
      <acl xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <aclGroups>
          <aclGroup operation="delete">
            <aclNumOrName>%s</aclNumOrName>
          </aclGroup>
        </aclGroups>
      </acl>
    </config>
'''

#静态路由NetConf接口：<ifName>NULL0</ifName> 是填写Tunnel name
# ip route-static 3.3.3.4 255.255.255.255 Tunnel6
# Args:
#   1. prefix 3.3.3.4
#   2. maskLength 32
#   2. ifName Tunnel6
hw_del_route_static_config = '''
    <config>
      <staticrt xmlns="http://www.huawei.com/netconf/vrp" content-version="1.0" format-version="1.0">
        <staticrtbase>
          <srRoutes>
            <srRoute operation="delete">
              <vrfName>_public_</vrfName>
              <afType>ipv4unicast</afType>
              <topologyName>base</topologyName>
              <prefix>%s</prefix>
              <maskLength>%s</maskLength>
              <ifName>%s</ifName>
              <destVrfName>_public_</destVrfName>
              <nexthop>0.0.0.0</nexthop>
            </srRoute>
          </srRoutes>
        </staticrtbase>
      </staticrt>
    </config>
'''

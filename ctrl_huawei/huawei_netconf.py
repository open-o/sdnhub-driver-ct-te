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

import logging
from ncclient import manager
from ncclient import transport
from nc_template import *
import re
import traceback
import time

logging.basicConfig(level=logging.INFO)

hw_netconf_user = 'huawei'
hw_netconf_passwd = 'Huawei@123'
hw_netconf_passwd_R5 = 'Root@123'
hw_netconf_host = '219.142.69.235'
hw_netconf_port = '830'


ip2num = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
num2ip = lambda x: '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])
# maskbits2ip = lambda x: num2ip((0xFFFFFFFF >> (32-x)) << (32-x))
rev_maskbits2ip = lambda x: num2ip(~((0xFFFFFFFF >> (32-x)) << (32-x)))
reverse_mask = lambda x:num2ip(~ip2num(x))

make_subif_cmd = lambda i,s: 'interface g' + str(i) + '/0' + (('.'+ str(s)) if s > 0 else '')

loopback_interface_map = {
    '4.4.4.4':'GigabitEthernet1/0/5',
    '5.5.5.5':'GigabitEthernet3/1/0',
    '3.3.3.3':'GigabitEthernet1/0/4',
    '1.1.1.1':'GigabitEthernet1/0/20',
    '11.11.11.11':'GigabitEthernet1/0/22',
}

# HKEY_CURRENT_USER\SoftWare\SimonTatham\PuTTY\SshHostKeys
# Drop a breakpoint at line 316 of $(PY)/Lib/site-packages/ncclient/operations/rpc.py to view the request XML.

def do_nc_query(func):
    def _do_nc_query(*args, **kwargs):
        resp, e = None, None
        try:
            resp = func(*args, **kwargs)
        except Exception, e:
            logging.error('Error in NC ' + str(func) + ':' + str(e))
            return resp, e
        return resp, e
    return _do_nc_query

class HW_NetConf(object):

    def __init__(self, host=hw_netconf_host, port=hw_netconf_port, username = hw_netconf_user, password = hw_netconf_passwd, timeout = 10):
        self.host = host
        self.port = port
        self.user = username
        self.passwd = password
        self.timeout = timeout
        self.acl_num = 3002
        self.pbr_node = 533

        pass


    def connect(self):

        m = None
        retry = 3
        while True:
            if retry <= 0:
                logging.error('Giveup SSH connect')
                break
            try:
                m = manager.connect(host=self.host,
                                       port=self.port,
                                       username=self.user,
                                       password=self.passwd,
                                       timeout=self.timeout,
                                       hostkey_verify=False,
                                       device_params={'name':'huawei'}
                                    )
                logging.info('connect manager:' + str(m))
                break
            except Exception, e:
                logging.error('SSH Connect Fail. Reason:' + str(e))
                retry -= 1
        return m

    def pick_reply_value(self, rep_str, pats):
        if rep_str is None:
            return {}

        vals = {}
        try:
            for k in pats:
                pat = pats[k]
                m = pat.search(rep_str)
                vals[k] = None
                if m:
                    grp = m.groups()
                    if grp and len(grp) > 0:
                        vals[k] = grp[0]
                continue
        except:
            logging.error('Pick value error')
            traceback.print_exc()
        return vals


    def check_response(self,rpc_obj, snippet_name):
        if rpc_obj is None:
            logging.error('No Response can be checked.')
            return -1
        logging.debug("RPCReply for %s is %s" % (snippet_name, rpc_obj.xml))
        xml_str = rpc_obj.xml
        if "ok/>" in xml_str or "ok />" in xml_str :
            logging.info("%s successful" % snippet_name)
            return 0
        else:
            logging.error("Cannot successfully execute: %s" % snippet_name)
            return -1

    #########################################################
    #  Wrapper of ncclient query
    #########################################################
    @do_nc_query
    def edit_config(self, conn = None, req = None):
        return conn.edit_config(target='running', config=req)
    @do_nc_query
    def get(self, conn = None, req = None):
        return conn.get(('subtree', req))
    @do_nc_query
    def action(self, conn = None, req = None):
        return conn.action(action=req)
    @do_nc_query
    def cli(self, conn = None, req = None):
        return conn.cli(command=req)



    #########################################################

    def get_interface_index(self, m, intf, sub_if=0):

        if_name = 'GigabitEthernet' + str(intf) + '/0'
        if sub_if != 0:
            if_name += '.' + str(sub_if)

        req = h3c_get_ifindex % if_name
        resp, e = self.get(conn=m, req=req)
        val = self.pick_reply_value(resp.data_xml, h3c_get_ifindex_reply_pat)
        if val and 'IfIndex' in val:
            return val['IfIndex']

        logging.error('Get interface index error')
        return -1

    def get_interface_caps(self, intf):
        ret = 0
        with self.connect() as m:
            ifidx = self.get_interface_index(m, intf)
            req = h3c_if_caps % ifidx
            resp,e = self.get(conn=m, req=req)
            req = h3c_if_status % ifidx
            resp, e = self.get(conn=m, req=req)
            pass


    def speed_limit(self, intf, speed):
        ret = 0
        with self.connect() as m:
            ifidx = self.get_interface_index(m, intf)
            req = h3c_car_limit % (ifidx, 1, speed, speed*4)
            resp,e = self.edit_config(conn=m,  req=req)
            ret = self.check_response(resp, 'speed_limit')
            pass

        return ret

    def del_acl(self, acl_num):
        ret = 0
        with self.connect() as m:
            req = h3c_acl_rule_del % (acl_num, acl_num)
            resp,e = self.edit_config(conn=m,  req=req)
            ret = self.check_response(resp, 'ACL DELETE')
        return ret


    def add_acl(self, acl_num, ip, mask, dir, action):
        ret = 0
        with self.connect() as m:
            resp,e = self.edit_config(conn=m,  req=h3c_acl_group % acl_num)
            ret = self.check_response(resp, 'ACL Group')

            if dir == 1:
                ' Inbound '
                req = h3c_acl_rule_in % (acl_num, acl_num, action, ip, reverse_mask(mask))
            else:
                ' Outbound '
                req = h3c_acl_rule_out % (acl_num, acl_num, action, ip, reverse_mask(mask))

            resp,e = self.edit_config(conn=m,  req=req)
            ret = self.check_response(resp, 'ACL RULE')

            pass
        return ret

    def apply_acl(self, intf, sub_if, dir, acl_num):
        with self.connect() as m:
            ifidx = self.get_interface_index(m, intf, sub_if)
            req = h3c_acl % (ifidx, dir, acl_num)
            resp,e = self.edit_config(conn=m,  req=req)
            ret = self.check_response(resp, 'Apply ACL to interface')
            pass


    def add_sub_if(self, intf, sub_if, ip, mask):
        '''
        :param intf: Interface name, e.g. GigabitEthernet0/1
        :param sub_if: sub interface number
        :param ip: IP of the sub interface.
        :param mask: Mask of IP subnet
        :return:
        '''
        ret = 0
        with self.connect() as m:
            subidx = -1
            subidx = self.get_interface_index(m, intf, sub_if)
            if subidx > 0:
                # The subif already exists, set sub ip to it.
                req = make_subif_cmd(intf, sub_if)
                req += '\n#\n ip address %s %s sub' % (ip, mask)
                resp, e = self.cli(conn=m, req = make_cli(req))
                pass
            else:
                # The sub if does not exists, create it and set ip.
                ifidx = self.get_interface_index(m, intf)
                req = h3c_sub_add_if % (ifidx, sub_if)
                resp,e = self.action(conn=m, req=req)
                ret = self.check_response(resp, 'Add Sub interface')

                #Form the sub interface name and get ifidx of sub interface
                subidx = self.get_interface_index(m, intf, sub_if)
                req = h3c_set_ip % (subidx, ip,  mask)
                resp,e = self.edit_config(conn=m,  req=req)
                ret = self.check_response(resp, 'Set IP to subinterface')

        return ret

    def set_vlan(self, intf, sub_if, vlan):
        ret = 0
        with self.connect() as m:
            req = make_subif_cmd(intf, sub_if) + '\n#\n'
            req += 'vlan-type dot1q vid ' + str(vlan)
            resp,e = self.cli(conn=m, req=make_cli(req))
        return ret


    def rm_sub_if(self, intf, sub_if):
        '''
        :param intf: Interface name, e.g. GigabitEthernet0/1
        :param sub_if: sub interface number
        :return:
        '''
        ret = 0
        with self.connect() as m:
            #Form the sub interface name and get ifidx of sub interface
            subidx = self.get_interface_index(m, intf, sub_if)
            req = h3c_sub_rm_if % subidx
            resp,e = self.action(conn=m, req=req)
            ret = self.check_response(resp, 'Delete subinterface')
        return ret


    def add_1to1_nat(self, intf, subif, pub_ip, priv_ip):
        '''
        :param pub_ip: Global IP
        :param priv_ip: local IP
        :return:
        '''
        ret = 0
        with self.connect() as m:
            # Check if the pub_ip is already mapped. If so, delete it firstly.
            req = h3c_get_nat % (pub_ip, 32)
            resp, e = self.get(conn=m, req = req)
            ip = self.pick_reply_value(resp.data_xml, h3c_get_nat_reply_pat)

            if ip and 'StartIpv4Address' in ip and ip['StartIpv4Address'] and len(ip['StartIpv4Address']) > 0:
                'Already exists NAT for this  IP'
                req = 'undo nat static outbound %s' % (ip['StartIpv4Address'])
                resp,e = self.cli(conn=m, req=make_cli(req))

            if priv_ip:
                req = make_subif_cmd(intf, subif) + '\n#\n' + 'nat static enable'
                resp, e = self.cli(conn=m, req=make_cli(req))
                req = h3c_nat_map % (priv_ip, priv_ip, pub_ip, 32, 'false')
                resp,e = self.edit_config(conn=m,  req=req)
                ret = self.check_response(resp, 'NAT 1 to 1 Mapping')
        return ret


    def add_dyna_nat(self, intf, sub_if,  pub_ip, subnet, mask):
        '''
        :param pub_ip: Global IP
        :param subnet: local IP
        :param mask: subnet mask
        :return:
        '''
        ret = 0
        with self.connect() as m:
            # req = 'acl advanced 3008\n#\n rule 10 permit ip destination %s %s' % (subnet, mask)
            # self.cli(conn=m, method='cli', req=make_cli(req))
            req = make_subif_cmd(intf, sub_if)
            req += '\n#\n nat outbound'
            self.cli(conn=m,  req=make_cli(req))
        return ret


    def add_cloud_pbr(self, intf, dst_ip, mask, next_hop):
        ret = 0
        with self.connect() as m:
            ifidx = self.get_interface_index(m, intf)

            #Create an ACL
            self.acl_num += 1
            req = h3c_acl_rule_in % (self.acl_num, self.acl_num, dst_ip, 2, reverse_mask(mask))
            resp,e = self.edit_config(conn=m,  req=req)
            ret = self.check_response(resp, 'ACL RULE')

            #Create PBR Node
            self.pbr_node += 1
            req = h3c_pbr_node % ('PBR_' + str(self.pbr_node), self.pbr_node, self.acl_num)
            resp,e = self.edit_config(conn=m,  req=req)
            ret = self.check_response(resp, 'PBR Node')

            #Add Apply nexthop
            req = h3c_pbr_nexthop % ('PBR_' + str(self.pbr_node), self.pbr_node, next_hop)
            resp,e = self.edit_config(conn=m,  req=req)
            ret = self.check_response(resp, 'PBR Nexthop')

            #apply PBR to interface
            req == h3c_pbr_apply_if2 % ('PBR_' + str(self.pbr_node), ifidx)
            resp,e = self.edit_config(conn=m,  req=req)
            ret = self.check_response(resp, 'PBR Apply')

        return ret

    def send_cli(self, req):
        ret = 0
        with self.connect() as m:
            resp,e = self.cli(conn=m, req=make_cli(req))
            print(type(resp))
            # print(resp)
        return ret

    def create_tunnel(self, m, tunnelName, mplsTunnelEgressLSRId, mplsTunnelIndex,
                      mplsTeTunnelSetupPriority, holdPriority, mplsTunnelBandwidth, includeAny = '', excludeAny = '', hotStandyEnable='false'):
         # Args:
        #   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
        #   2. mplsTunnelEgressLSRId
        #   3. mplsTunnelIndex
        #   4. mplsTeTunnelSetupPriority
        #   5. holdPriority
        #   6. mplsTunnelBandwidth (100Kbps)
        #   7. includeAny (0x1)
        #   8. excludeAny (0x2)
        ret = 0
        req = hw_create_tunnel % (tunnelName, mplsTunnelEgressLSRId, mplsTunnelIndex,
                                  mplsTeTunnelSetupPriority, holdPriority, mplsTunnelBandwidth, includeAny, excludeAny)
        resp,e = self.edit_config(conn=m, req=req)
        '''
        <?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply message-id="urn:uuid:7c559e22-8b04-4a53-8e0e-ea440896f730" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" flow-id="56">
            <ok/>
        </rpc-reply>
        '''
        ret = self.check_response(resp, 'Create tunnel')
        return ret

    def create_tunnel_with_hops(self, m, tunnelName, mplsTunnelEgressLSRId, mplsTunnelIndex,
                      mplsTeTunnelSetupPriority, holdPriority, mplsTunnelBandwidth, explicitPathName):
         # Args:
        #   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
        #   2. mplsTunnelEgressLSRId
        #   3. mplsTunnelIndex
        #   4. mplsTeTunnelSetupPriority
        #   5. holdPriority
        #   6. mplsTunnelBandwidth (100Kbps)
        ret = 0
        req = hw_create_tunnel_with_hops % (tunnelName, mplsTunnelEgressLSRId, mplsTunnelIndex,
                  mplsTeTunnelSetupPriority, holdPriority, mplsTunnelBandwidth, explicitPathName)
        resp,e = self.edit_config(conn=m, req=req)
        '''
        <?xml version="1.0" encoding="UTF-8"?>
        <rpc-reply message-id="urn:uuid:7c559e22-8b04-4a53-8e0e-ea440896f730" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" flow-id="56">
            <ok/>
        </rpc-reply>
        '''
        ret = self.check_response(resp, 'Create tunnel with hops')
        return ret

    def create_primary_path_name(self, m, explicitPathName):
        #1.创建显示路径主路径名称
        # explicit-path a-b-pri      //主显示路径
        # Args:
        #   1. explicitPathName primary explicit path Name
        ret = 0
        req = hw_create_primary_path_name % (explicitPathName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_create_primary_path_name')
        return ret

    def create_primary_path_hop_detail(self, m, explicitPathName, hoplist):
        #3.创建主路径每一跳
        # next hop 10.1.12.1
        # next hop 10.1.12.2
        # Args:
        #   1. primary explicit path Name
        #   2. primary path hop items string
        # Args:
        #   1. mplsTunnelHopIndex
        #   2. mplsTunnelHopIpAddr
        ret = 0
        hops = ''
        hop_index = 1
        for hop_item in hoplist:
            hop_str = hw_create_primary_path_hop_item % (str(hop_index), hop_item)
            hops += hop_str
            hop_index += 1
        req = hw_create_primary_path_hop_container % (explicitPathName, hops)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_create_primary_path_hop_detail')
        return ret

    def tunnel_config(self, m, tunnelName, explicitPathName):
        # 6.RSVP-TE隧道路径配置
        # Args:
        #   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
        #   2. explicitPathName
        ret = 0
        req = hw_tunnel_config % (tunnelName, explicitPathName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_tunnel_config')
        return ret

    def tunnel_igp_config(self, m, tunnelName):
        # 隧道的IGP属性配置
        # mpls te igp shortcut isis  #配置IGP Shortcut
        # mpls te igp metric absolute 5 #配置TE隧道的IGP度量
        # Args:
        #   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
        ret = 0
        req = hw_tunnel_igp_config % (tunnelName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_tunnel_igp_config')
        return ret

    def tunnel_isis_config(self, m, tunnelName):
        # ISIS使能配置
        # isis enable 100 #使能隧道接口的IS-IS进程
        # Args:
        #   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
        ret = 0
        req = hw_tunnel_isis_config % (tunnelName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_tunnel_isis_config')
        return ret

    def tunnel_mainIpAddr_config(self, m, ifName):
        # 配置主地址
        # ip address unnumbered interface LoopBack0 #配置路由发布
        # Args:
        #   1. ifName,eg:Tunnel5(Tunnel prefix is necessary)
        ret = 0
        req = hw_tunnel_mainIpAddr_config % (ifName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_tunnel_mainIpAddr_config')
        return ret

    def tunnel_statistic_enable(self, m, tunnelName):
        # Tunnel下开启计数
        # statistic enable
        # Args:
        #   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
        ret = 0
        req = hw_tunnel_statistic_enable % (tunnelName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_tunnel_statistic_enable')
        return ret

    def add_acl(self, m, aclNumOrName):
        # Args:
        #   1. aclNumOrName 3050
        ret = 0
        req = hw_add_acl % (aclNumOrName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'Add acl')
        return ret

    def add_rule(self, m, aclNumOrName, aclRuleName, aclRuleID, aclAction, aclSourceIp = '', aclSrcWild = '', aclDestIp = '', aclDestWild = ''):
        # Args:
        #   1. aclNumOrName 3050
        #   2. aclRuleID 5
        #   3. aclAction permit
        #   4. aclSourceIp 10.0.1.10
        #   5. aclSrcWild 0.0.0.255
        #   6. aclDestIp 10.0.1.10
        #   7. aclDestWild 0.0.0.255
        ret = 0
        req = hw_add_rule % (aclNumOrName, aclRuleName, aclRuleID, aclAction, aclSourceIp, aclSrcWild, aclDestIp, aclDestWild)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'Add rule')
        return ret

    def add_classifier(self, m, classifierName):
        # Args:
        #   1. classifierName flow11to3
        ret = 0
        req = hw_add_classifier % (classifierName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'add_classifier')
        return ret

    def classifier_match_rule(self, m, classifierName, aclName):
        # Args:
        #   1. classifierName flow11to3
        #   2. aclName 3050
        ret = 0
        req = hw_classifier_match_rule % (classifierName, aclName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'classifier_match_rule')
        return ret


    def add_behavior(self, m, behaviorName):
        # Args:
        #   1. behaviorName flow_redirect
        ret = 0
        req = hw_add_behavior % (behaviorName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'add_behavior')
        return ret


    def add_behavior_action(self, m, behaviorName, nextHop):
        # Args:
        #   1. behaviorName flow_redirect
        #   2. nextHop 3.3.3.3
        ret = 0
        req = hw_add_behavior_action % (behaviorName, nextHop)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'add_behavior_action')
        return ret


    def add_policy(self, m, policyName):
        # Args:
        #   1. policyName flow_policy
        ret = 0
        req = hw_add_policy % (policyName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'add_policy')
        return ret


    def add_policy_action(self, m, policyName, classifierName, behaviorName):
        # Args:
        #   1. policyName flow_policy
        #   2. classifierName flow11to3
        #   3.  flow_redirect
        ret = 0
        req = hw_add_policy_action % (policyName, classifierName, behaviorName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'add_policy_action')
        return ret


    def apply_policy_to_interface(self, m, ifName, policyName):
        # Args:
        #   1. ifName GigabitEthernet1/0/22
        #   2. policyName flow_policy
        ret = 0
        req = hw_apply_policy_to_interface % (ifName, policyName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'apply_policy_to_interface')
        return ret

    def create_intf_ip(self, m, ifName, ifIpAddr, subnetMask):
        # Args:
        #   1. ifName LoopBack1
        #   2. ifIpAddr 3.3.3.4
        #   3. subnetMask 255.255.255.255
        ret = 0
        req = hw_create_intf_ip % (ifName, ifIpAddr, subnetMask)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_create_intf_ip')
        return ret

    def route_static_config(self, m, prefix,  maskLength, ifName):
        # Args:
        #   1. prefix 3.3.3.4
        #   2. maskLength 32
        #   2. ifName Tunnel6
        ret = 0
        req = hw_route_static_config % (prefix,  maskLength, ifName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_route_static_config')
        return ret

    def link_property_config(self, m, ifName, property_value):
        # Args:
        #   1. ifName GigabitEthernet1/0/0
        #   2. adminGroups 0x2
        ret = 0
        req = hw_link_property_config % (ifName, property_value)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_link_property_config')
        return ret

    def del_tunnel(self, m, tunnelName):
        # Args:
        #   1. tunnelName,eg:Tunnel5(Tunnel prefix is necessary)
        ret = 0
        req = hw_del_tunnel % (tunnelName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_del_tunnel')
        return ret

    def del_primary_path_name(self, m, explicitPathName):
        # Args:
        #   1. explicitPathName
        ret = 0
        req = hw_del_primary_path_name % (explicitPathName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_del_primary_path_name')
        return ret

    def del_intf_ip(self, m, ifName):
        # Args:
        #   1. ifName LoopBack1
        ret = 0
        req = hw_del_intf_ip % (ifName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_del_intf_ip')
        return ret

    def undo_policy_to_interface(self, m, ifName, policyName):
        # Args:
        #   1. ifName GigabitEthernet1/0/22
        #   2. policyName flow_policy
        ret = 0
        req = hw_undo_policy_to_interface % (ifName, policyName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_undo_policy_to_interface')
        return ret

    def del_pol_beh_cls(self, m, policyName, behaviorName, classifierName):
        # Args:
        #   1. policyName flow_policy
        #   2. behaviorName flow_redirect
        #   3. classifierName flow11to3
        ret = 0
        req = hw_del_pol_beh_cls % (policyName, behaviorName, classifierName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_del_pol_beh_cls')
        return ret

    def del_acl(self, m, aclNumOrName):
        # Args:
        #   1. aclNumOrName 3050
        ret = 0
        req = hw_del_acl % (aclNumOrName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_del_acl')
        return ret

    def del_route_static_config(self, m, prefix, maskLength, ifName):
        # Args:
        #   1. prefix 3.3.3.4
        #   2. maskLength 32
        #   2. ifName Tunnel6
        ret = 0
        req = hw_del_route_static_config % (prefix, maskLength, ifName)
        resp,e = self.edit_config(conn=m, req=req)
        ret = self.check_response(resp, 'hw_del_route_static_config')
        return ret

    def hw_link_property_config_netconf(self, req = None):
        ret = 0
        ifName = req['intf']
        property_value = req['link_property']
        with self.connect() as m:
            ret = self.link_property_config(m, ifName, property_value)
            pass
        return ret

    def hw_create_intf_ip_netconf(self, req = None):
        ret = 0
        with self.connect() as m:
            ret = self.create_intf_ip(m,req['to_loopback_id'], req['to_loopback_ip'],'255.255.255.255')
            pass
        return ret

    def hw_del_intf_ip_netconf(self, req = None):
        ret = 0
        with self.connect() as m:
            ret = self.del_intf_ip(m, req['to_loopback_id'])
            pass
        return ret

    def hw_create_tunnel_netconf(self, para=None):
        ret = 0
        # req_test['includeAny']
        # req_test['excludeAny']
        tunnelName = para['name']
        tunnelPriority = str(para['priority'])
        tunnelBW = str(int(para['bandwidth'])*1000)

        with self.connect() as m:
            if ('hop_list' in para and para['hop_list'].__len__() > 0):
                ret = self.create_primary_path_name(m, 'primary_' + tunnelName)
                ret = self.create_primary_path_hop_detail(m, 'primary_' + tunnelName, para['hop_list'])
                ret = self.create_tunnel_with_hops(m, tunnelName, para['to_router_uid'], para['uid'],
                                     tunnelPriority, tunnelPriority, tunnelBW, 'primary_' + tunnelName)
            # if ('hop_list' in para and para['hop_list'].__len__() > 0):
            #     ret = self.create_primary_path_name(m, 'primary_' + tunnelName)
            #     ret = self.create_primary_path_hop_detail(m, 'primary_' + tunnelName, para['hop_list'])
            #     ret = self.tunnel_config(m, tunnelName, 'primary_' + tunnelName)
            #     pass
            else:
                ret = self.create_tunnel(m, tunnelName, para['to_router_uid'], para['uid'],
                                         tunnelPriority, tunnelPriority, tunnelBW, para['includeAny'], para['excludeAny'], hotStandyEnable='false')
        return ret

    def hw_del_tunnel_netconf(self, para=None):
        ret = 0
        # req_test['includeAny']
        # req_test['excludeAny']
        tunnelName = para['name']
        with self.connect() as m:
            ret = self.del_tunnel(m, tunnelName)
            if ('hop_list' in para and para['hop_list'].__len__() > 0):
                ret = self.del_primary_path_name(m, 'primary_' + tunnelName)
        return ret

    def hw_redirect_to_tunnel_netconf(self, req = None):
        ret = 0
        '''
        req_test = {}
        req_test['tunnel_name'] = 'Tunnel' + args["tunnel_name"]
        req_test['to_router_uid'] = '11.11.11.11'#einfo.fr_uid(req['to_router_uid']).get("ip_str")
        req_test['from_router_uid'] = '3.3.3.3'#einfo.fr_uid(req['from_router_uid']).get("ip_str")
        req_test['ipv4_src'] = req['ipv4_src']
        req_test['ipv4_dst'] = req['ipv4_dst']
        req['to_loopback_id']
        req['to_loopback_ip']
        '''
        ifName = loopback_interface_map[req['from_router_uid']]
        next_hop = req['to_loopback_ip']
        tunnelName = req['tunnel_name']
        sourceIp = ''
        src_mask = ''
        desIp = ''
        des_mask = ''
        if ('ipv4_src' in req and req['ipv4_src'].__len__() > 0):
            src_ip_str = req['ipv4_src']
            sourceIp, src_mask_num = src_ip_str.split('/')
            src_mask = rev_maskbits2ip(int(src_mask_num))#'0.0.0.255'
        if ('ipv4_dst' in req and req['ipv4_dst'].__len__() > 0):
            des_ip_str = req['ipv4_dst']
            desIp, des_mask_num = des_ip_str.split('/')
            des_mask = rev_maskbits2ip(int(des_mask_num))#'0.0.0.255'
        acl_num = '3050'
        with self.connect() as m:
            #config tunnel property
            # ret = self.tunnel_igp_config(m, tunnelName)
            # ret = self.tunnel_isis_config(m, tunnelName)
            ret = self.tunnel_mainIpAddr_config(m, tunnelName)
            ret = self.tunnel_statistic_enable(m, tunnelName)
            ret = self.route_static_config(m, next_hop, '32', tunnelName)

            ret = self.add_acl(m, acl_num)
            ret = self.add_rule(m, acl_num, 'rule_5', '5', 'permit', sourceIp, src_mask, desIp, des_mask)
            ret = self.add_classifier(m,'cls_' + tunnelName)
            ret = self.classifier_match_rule(m, 'cls_' + tunnelName, acl_num)
            ret = self.add_behavior(m, 'behavior_' + tunnelName)
            ret = self.add_behavior_action(m, 'behavior_' + tunnelName, next_hop)
            ret = self.add_policy(m, 'policy_' + tunnelName)
            ret = self.add_policy_action(m, 'policy_' + tunnelName, 'cls_' + tunnelName, 'behavior_' + tunnelName)
            ret = self.apply_policy_to_interface(m, ifName, 'policy_' + tunnelName)
        return ret

    def hw_redirect_to_tunnel_max_nums_netconf(self, req = None):
        ret = 0
        '''
        req_test = {}
        req_test['tunnel_name'] = 'Tunnel' + args["tunnel_name"]
        req_test['to_router_uid'] = '11.11.11.11'#einfo.fr_uid(req['to_router_uid']).get("ip_str")
        req_test['from_router_uid'] = '3.3.3.3'#einfo.fr_uid(req['from_router_uid']).get("ip_str")
        req_test['ipv4_src'] = req['ipv4_src']
        req_test['ipv4_dst'] = req['ipv4_dst']
        req['to_loopback_id']
        req['to_loopback_ip']
        '''
        ifName = loopback_interface_map[req['from_router_uid']]
        next_hop = req['to_loopback_ip']
        tunnelName = req['tunnel_name']
        sourceIp = ''
        src_mask = ''
        desIp = ''
        des_mask = ''
        if ('ipv4_src' in req and req['ipv4_src'].__len__() > 0):
            src_ip_str = req['ipv4_src']
            sourceIp, src_mask_num = src_ip_str.split('/')
            src_mask = rev_maskbits2ip(int(src_mask_num))#'0.0.0.255'
        if ('ipv4_dst' in req and req['ipv4_dst'].__len__() > 0):
            des_ip_str = req['ipv4_dst']
            desIp, des_mask_num = des_ip_str.split('/')
            des_mask = rev_maskbits2ip(int(des_mask_num))#'0.0.0.255'
        acl_num = '3050'
        with self.connect() as m:
            #config tunnel property
            # ret = self.tunnel_igp_config(m, tunnelName)
            # ret = self.tunnel_isis_config(m, tunnelName)
            ret = self.tunnel_mainIpAddr_config(m, tunnelName)
            ret = self.tunnel_statistic_enable(m, tunnelName)
            ret = self.route_static_config(m, next_hop, '32', tunnelName)

            ret = self.add_classifier(m,'cls_' + tunnelName)
            # 4 acl(16000 rule) start
            for acl in range(3050, 3050+4):
                acl_num = str(acl)
                print 'acl ' + acl_num
                ret = self.add_acl(m, acl_num)
                for rule_step in range(1, 1 + 16000):
                    rule_id = str(5 + rule_step)
                    if sourceIp and sourceIp.__len__() > 1:
                        sourceIp = num2ip(ip2num(sourceIp) + 1)
                    if desIp and desIp.__len__() > 1:
                        desIp = num2ip(ip2num(desIp) + 1)
                    print(rule_id + '/' + sourceIp + '_' + desIp)
                    ret = self.add_rule(m, acl_num, 'rule_' + rule_id, rule_id, 'permit', sourceIp, src_mask, desIp, des_mask)
                ret = self.classifier_match_rule(m, 'cls_' + tunnelName, acl_num)
            # 4 acl(16000 rule) end
            ret = self.add_behavior(m, 'behavior_' + tunnelName)
            ret = self.add_behavior_action(m, 'behavior_' + tunnelName, next_hop)
            ret = self.add_policy(m, 'policy_' + tunnelName)
            ret = self.add_policy_action(m, 'policy_' + tunnelName, 'cls_' + tunnelName, 'behavior_' + tunnelName)
            ret = self.apply_policy_to_interface(m, ifName, 'policy_' + tunnelName)
        return ret

    def hw_undo_redirect_to_tunnel_netconf(self, req = None):
        ret = 0
        '''
        req_test = {}
        req_test['tunnel_name'] = 'Tunnel' + args["tunnel_name"]
        req_test['to_router_uid'] = '11.11.11.11'#einfo.fr_uid(req['to_router_uid']).get("ip_str")
        req_test['from_router_uid'] = '3.3.3.3'#einfo.fr_uid(req['from_router_uid']).get("ip_str")
        req_test['ipv4_src'] = req['ipv4_src']
        req_test['ipv4_dst'] = req['ipv4_dst']
        req['to_loopback_id']
        req['to_loopback_ip']
        '''
        ifName = loopback_interface_map[req['from_router_uid']]
        next_hop = req['to_loopback_ip']
        tunnelName = req['tunnel_name']
        acl_num = '3050'
        with self.connect() as m:
            ret = self.undo_policy_to_interface(m, ifName, 'policy_' + tunnelName)
            ret = self.del_pol_beh_cls(m, 'policy_' + tunnelName, 'behavior_' + tunnelName, 'cls_' + tunnelName)
            ret = self.del_acl(m, acl_num)
            ret = self.del_route_static_config(m, next_hop, '32', tunnelName)
        return ret

    def hw_add_rule_to_redirected_tunnel_netconf(self, req = None):
        ret = 0
        '''
        req_test = {}
        req_test['tunnel_name'] = 'Tunnel' + args["tunnel_name"]
        req_test['to_router_uid'] = '11.11.11.11'#einfo.fr_uid(req['to_router_uid']).get("ip_str")
        req_test['from_router_uid'] = '3.3.3.3'#einfo.fr_uid(req['from_router_uid']).get("ip_str")
        req_test['ipv4_src'] = req['ipv4_src']
        req_test['ipv4_dst'] = req['ipv4_dst']
        req_test['rule_id']
        req['to_loopback_id']
        req['to_loopback_ip']
        '''
        ifName = loopback_interface_map[req['from_router_uid']]
        next_hop = req['to_loopback_ip']
        tunnelName = req['tunnel_name']
        sourceIp = ''
        src_mask = ''
        desIp = ''
        des_mask = ''
        if ('ipv4_src' in req and req['ipv4_src'].__len__() > 0):
            src_ip_str = req['ipv4_src']
            sourceIp, src_mask_num = src_ip_str.split('/')
            src_mask = rev_maskbits2ip(int(src_mask_num))#'0.0.0.255'
        if ('ipv4_dst' in req and req['ipv4_dst'].__len__() > 0):
            des_ip_str = req['ipv4_dst']
            desIp, des_mask_num = des_ip_str.split('/')
            des_mask = rev_maskbits2ip(int(des_mask_num))#'0.0.0.255'
        acl_num = '3050'
        rule_id = req['rule_id']
        with self.connect() as m:
            ret = self.add_rule(m, acl_num, 'rule_' + rule_id, rule_id, 'permit', sourceIp, src_mask, desIp, des_mask)
        return ret

if __name__ == '__main__':
    # hwnc = HW_NetConf( host='202.102.40.71', port=830, username = 'admin', password = 'admin')
    # hwnc = HW_NetConf( host='219.142.69.234', port=830, username = hw_netconf_user, password = hw_netconf_passwd)
    #3.3.3.3
    # hwnc = HW_NetConf( host='219.142.69.235', port=18003, username = hw_netconf_user, password = hw_netconf_passwd)
    #11.11.11.11
    # hwnc = HW_NetConf( host='219.142.69.235', port=18011, username = hw_netconf_user, password = hw_netconf_passwd)
    #1.1.1.1
    hwnc = HW_NetConf( host='219.142.69.235', port=18001, username = hw_netconf_user, password = hw_netconf_passwd)

    # hwnc.send_cli('pwd')
    # req = {
    #         "uid": "46",
    #         "hop_list": ['10.230.10.2', '10.230.10.10'],
    #         "from_router_name": "",
    #         "to_router_name": "",
    #         "bandwidth": "100",
    #         "to_router_uid": "11.11.11.11",
    #         "from_router_uid": "3.3.3.3",
    #         "callback": "http://127.0.0.1/path",
    #         "name": "311",
    #         "priority": 7,
    #         "delay": "",
    #         "autoApprove": "false"
    #     }
    # hwnc.hw_create_tunnel_netconf(req)
    # hwnc.hw_redirect_to_tunnel_netconf(None)
    hwnc.hw_create_intf_ip_netconf('LoopBack2', '3.3.3.5', '255.255.255.255')

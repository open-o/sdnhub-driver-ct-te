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


import os
import sys

curdir = os.path.dirname(os.path.realpath(__file__))
miedir = os.path.join(curdir, "..", "mie")
sys.path.append(miedir)

import traceback
import time
import httplib
import ssl
import json
import datetime

from bprint import varprt, varfmt
from xlogger import klog
from dotdict import DotDict
from confcenter import XConfCenter

from huawei_netconf import *

klog.to_stdout()

cfgfile = os.path.join(curdir, "cfg")
conf = XConfCenter("huawei", [cfgfile])

klog.d("Loading %s ..." % __file__)
ip2num = lambda x:sum([256**j*int(i) for j,i in enumerate(x.split('.')[::-1])])
num2ip = lambda x: '.'.join([str(x/(256**i)%256) for i in range(3,-1,-1)])
### #####################################################################
## Helper
#

def_scheme = conf.xget("api_default/url/scheme", "https")
def_hostname = conf.xget("api_default/url/hostname", "172.19.45.185")
def_port = conf.xget("api_default/url/port", 8182)

def dmstr(dat):
    '''DotDict from a String'''

    try:
        dic = json.JSONDecoder().decode(str(dat))
    except:
        dic = {}
    return DotDict(**dic)


def hget(scheme, hostname, port, path, method="GET", dat=None, hdr=None, timeout=None):
    '''Http get'''

    hdr = hdr or {}
    hdr["Content-Type"] = hdr.get("Content-Type", "application/json")

    if scheme == "https":
        context = ssl._create_unverified_context()
        hc = httplib.HTTPSConnection(hostname, port, timeout, context=context)
    else:
        hc = httplib.HTTPConnection(hostname, port, timeout)

    params = json.dumps(dat)

    if method == "POST" and not params:
        klog.e("!!!!!!!! NO PARAMETERS FOR POST METHOD !!!!!!!!")

    klog.d()
    klog.d("+" * 30)
    klog.d(" METHOD : %s" % method)
    klog.d(" SCHEME : %s" % scheme)
    klog.d("   HOST : %s" % hostname)
    klog.d("   PORT : %s" % port)
    klog.d("   PATH : %s" % path)
    klog.d("   BODY : %s" % params)
    klog.d("HEADERS : %s" % json.dumps(hdr))

    hc.request(method, path, params, hdr)
    r = hc.getresponse()
    res = r.read()

    klog.d(" STATUS : %d" % r.status)
    klog.d(" REASON : %s" % r.reason)
    klog.d(varfmt(dmstr(res), "DUMP HGET DATA"))
    klog.d("-" * 30)
    klog.d()

    return r.status, r.reason, res


def call(cls, *args, **kwargs):
    api = cls()

    ok, reason, res = api.dotan(*args, **kwargs)
    if reason == "Unauthorized":
        token.token(True)
        ok, reason, res = api.dotan(*args, **kwargs)

    return ok, reason, res

    # return cls().dotan(*args, **kwargs)

### #####################################################################
## Token
#
class TokenGetter():
    def __init__(self):
        self.url_scheme = conf.xget("api_token/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_token/url/hostname", def_hostname)
        self.url_port = conf.xget("api_token/url/port", def_port)
        self.url_pathpat = "/controller/v2/tokens"

        self.token_str = None
        self.expired_time = 0

        username = conf.xget("api_tokenGetter/user/name", "kamasamikon@qq.com")
        userpass = conf.xget("api_tokenGetter/user/pass", "auv@3721.com")
        self.set_userinfo(username, userpass)

    def set_userinfo(self, username, userpass):
        self.username = username
        self.userpass = userpass

        self.userinfo = {"userName": self.username, "password": self.userpass}

    def _parsetime(self, timestr):
        # 2016-10-12T02:17:47,960+08:00

        try:
            x = timestr.split(',')[0]
            d = x.replace("T", "").replace(":", "").replace("-", "")
            return int(d)
        except:
            return self._nowtime() + 3600

    def _nowtime(self):
        now = datetime.datetime.now()
        now = "%04d%02d%02d%02d%02d%02d" % (now.year, now.month, now.day, now.hour, now.minute, now.second)
        return int(now)

    def _check_expire(self):
        now = self._nowtime()
        exp = self.expired_time

        # expire 10 seconds ahead.
        res = now > (exp + 10)
        return res

    def _get(self):
        # Get from remote
        status, reason, resp = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, "POST", self.userinfo)
        dic = dmstr(resp)

        try:
            data = dic["data"]
            self.token_str = data["token_id"]
            self.expired_time = self._parsetime(data["expiredDate"])
        except:
            klog.e("xxxxxxxxxxxxxxxxxxx")
            klog.e(traceback.format_exc())
            self.token_str = None
            self.expired_time = 0

    def token(self, refresh=False):
        if refresh or not self.token_str or self._check_expire():
            self._get()
        return self.token_str

    def todic(self, refresh=False):
        return {"X-Access-Token": self.token(refresh)}

token = TokenGetter()


### #####################################################################
## Equips
#
class EquipInfo():
    def __init__(self, map_uid_obj=None, map_loopback_uid=None, map_loopback_port=None,
                map_node_port_id_ip = None, map_link_ip_obj = None):
        self.set_map(map_uid_obj, map_loopback_uid, map_loopback_port,
                map_node_port_id_ip, map_link_ip_obj)

    def set_map(self, map_uid_obj=None, map_loopback_uid=None, map_loopback_port=None,
                map_node_port_id_ip = None, map_link_ip_obj = None):
        self.map_uid_obj = map_uid_obj or {}
        self.map_loopback_uid = map_loopback_uid or {}
        self.map_loopback_port = map_loopback_port or {}
        self.map_node_port_id_ip = map_node_port_id_ip or {}
        self.map_link_ip_obj = map_link_ip_obj or {}

    def fr_uid(self, uid):
        return self.map_uid_obj.get(uid)

    def fr_loopback(self, loopback):
        uid = self.map_loopback_uid.get(loopback)
        return self.fr_uid(uid)

    def fr_netconf_port(self, loopback):
        return self.map_loopback_port.get(loopback)

    def set_map_node_port_id_ip(self, map_node):
        self.map_node_port_id_ip = map_node

    def set_map_link_ip_obj(self, map_link):
        self.map_link_ip_obj = map_link

    def fr_link_ip_obj(self, link_ip):
        return self.map_link_ip_obj.get(link_ip)

einfo = EquipInfo()


### #####################################################################
## Apis
#
class AutoApproveConfigSet():
    ''' doc: 2.4.1 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_lspStatistic/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_lspStatistic/url/hostname", def_hostname)
        self.url_port = conf.xget("api_lspStatistic/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-lsp-reoptimization:lsp-reoptimization-cfg/autoapprove-config"
        self.method = "POST"

    def dotan(self):
        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res


class AutoApproveConfigQuery():
    ''' doc: 2.4.2 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_lspStatistic/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_lspStatistic/url/hostname", def_hostname)
        self.url_port = conf.xget("api_lspStatistic/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-lsp-reoptimization:lsp-reoptimization-cfg/autoapprove-config"
        self.method = "GET"

    def dotan(self):
        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res


class LspConfirm():
    ''' doc: 2.4.8 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_lspStatistic/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_lspStatistic/url/hostname", def_hostname)
        self.url_port = conf.xget("api_lspStatistic/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-lsp-reoptimization:lsp-reoptimization-cfg/confirming-lsp-infos"
        self.method = "GET"

    def dotan(self):
        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res


class PceAprove_2():
    ''' doc: 2.4.9 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_lspStatistic/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_lspStatistic/url/hostname", def_hostname)
        self.url_port = conf.xget("api_lspStatistic/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-lsp-reoptimization:lsp-reoptimization-cfg/pceAprove"
        self.method = "POST"

    def dotan(self, req):
        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res

class LspStatistic():
    ''' doc: 2.4.11 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_lspStatistic/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_lspStatistic/url/hostname", def_hostname)
        self.url_port = conf.xget("api_lspStatistic/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-lsp-reoptimization:lsp-reoptimization-cfg/lsp-statistic"
        self.method = "GET"

    def dotan(self):
        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res

class NeCfg_All():
    ''' doc: 2.1.1 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_neCfg_All/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_neCfg_All/url/hostname", def_hostname)
        self.url_port = conf.xget("api_neCfg_All/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-inventory:inventory-cfg/nes"
        self.method = "GET"

    def dotan(self):

        klog.d(varfmt(self))
        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res

class NeCfg_One():
    ''' doc: 2.1.5 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_neCfg_One/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_neCfg_One/url/hostname", def_hostname)
        self.url_port = conf.xget("api_neCfg_One/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-inventory:inventory-cfg/nes/{neid}"
        self.method = "GET"

    def dotan(self, neid):
        hdr = token.todic()
        url_pathpat = self.url_pathpat.format(neid=neid)
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res

class NeOper_All():
    ''' doc: 2.1.2 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_neOper_All/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_neOper_All/url/hostname", def_hostname)
        self.url_port = conf.xget("api_neOper_All/url/port", def_port)
        self.url_pathpat = "/restconf/operational/huawei-ac-inventory:inventory-oper/nes"
        self.method = "GET"

    def dotan(self):
        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res

class NeOper_One():
    ''' doc: 2.1.6 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_neOper_One/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_neOper_One/url/hostname", def_hostname)
        self.url_port = conf.xget("api_neOper_One/url/port", def_port)
        self.url_pathpat = "/restconf/operational/huawei-ac-inventory:inventory-oper/nes/{neid}"
        self.method = "GET"

    def dotan(self, neid):
        hdr = token.todic()
        url_pathpat = self.url_pathpat.format(neid=neid)
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res

class LspInfos():
    ''' doc: 2.4.6 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_lspInfos/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_lspInfos/url/hostname", def_hostname)
        self.url_port = conf.xget("api_lspInfos/url/port", def_port)
        self.url_pathpat = "/restconf/operational/huawei-ac-lsp-reoptimization:lsp-reoptimization-oper/lsp-infos"
        self.method = "GET"

    def dotan(self):
        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res

class L3_LinkCfg_All():
    ''' doc: 2.2.1 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_neCfg_All/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_neCfg_All/url/hostname", def_hostname)
        self.url_port = conf.xget("api_neCfg_All/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-network-te-topology:l3-topology-cfg/topologies/topology/4acbd130-846b-3536-a142-8a42d8a3c4b8/links"
        self.method = "GET"

    def dotan(self):

        klog.d(varfmt(self))
        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res

class L3_NodeCfg_All():
    ''' doc: 2.2.4 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_neCfg_All/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_neCfg_All/url/hostname", def_hostname)
        self.url_port = conf.xget("api_neCfg_All/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-network-te-topology:l3-topology-cfg/topologies/topology/4acbd130-846b-3536-a142-8a42d8a3c4b8/nodes"
        self.method = "GET"

    def dotan(self):

        klog.d(varfmt(self))
        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, res

class L3_Topo():
    def __init__(self):
        self.url_scheme = conf.xget("api_neCfg_All/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_neCfg_All/url/hostname", def_hostname)
        self.url_port = conf.xget("api_neCfg_All/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-network-te-topology:l3-topology-cfg/topologies/topology/4acbd130-846b-3536-a142-8a42d8a3c4b8/topo"
        self.method = "GET"

    def dotan(self):

        klog.d(varfmt(self))
        err, msg, res = call(L3_NodeCfg_All)
        if err:
            return -1, "Get L3_NodeCfg_All Information failed", None
        res = dmstr(res)
        # set node map content
        res_map_node = {}
        if (res and 'node' in res and res['node'].__len__ > 0):
            for node_item in res['node']:
                lsr_id = ''
                if ('te-attributes' in node_item and 'lsr-id' in node_item['te-attributes']):
                    lsr_id = node_item['te-attributes']['lsr-id']
                if ('ltps' in node_item and 'ltp' in node_item['ltps']
                    and node_item['ltps']['ltp'].__len__ > 0):
                    for ltp_item in node_item['ltps']['ltp']:
                        if ('id' in ltp_item and 'te-attributes' in ltp_item and 'ip-address' in ltp_item['te-attributes']):
                            res_map_node[ltp_item['id']] = lsr_id + '&' + ltp_item['te-attributes']['ip-address']
        einfo.set_map_node_port_id_ip(res_map_node)
        print res_map_node
        err, msg, res = call(L3_LinkCfg_All)
        if err:
            return -1, "Get L3_LinkCfg_All Information failed", None
        res = dmstr(res)
        res_map_link = {}
        if (res and 'link' in res and res['link'].__len__ > 0):
            for link_item in res['link']:
                if ('id' in link_item and 'left-ltp-id' in link_item and 'right-ltp-id' in link_item):
                    map_link_key = res_map_node[link_item['left-ltp-id']] + '_' + res_map_node[link_item['right-ltp-id']]
                    res_map_link[map_link_key] = link_item
        einfo.set_map_link_ip_obj(res_map_link)
        print res_map_link
        # 3. prepare the return value
        ret = res_map_link

        return 0, "L3_Topo get ok", ret

class L3_LinkCfg_Update():
    ''' doc: 2.2.8 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_pceReoptimizationByTunnel/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_pceReoptimizationByTunnel/url/hostname", def_hostname)
        self.url_port = conf.xget("api_pceReoptimizationByTunnel/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-network-te-topology:l3-topology-cfg/topologies/topology/4acbd130-846b-3536-a142-8a42d8a3c4b8/links"
        self.method = "PUT"

    def dotan(self, req=None):
        '''
        req: {
            "user-handle": "o:string",
            "auto-approve": "o:enum",
            "computation-priority": "o:int"
        }
        '''
        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, req, hdr)
        return 0 if status == 200 else -1, reason, res

class PceReoptimizationByTunnel():
    ''' doc: 2.4.4 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_pceReoptimizationByTunnel/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_pceReoptimizationByTunnel/url/hostname", def_hostname)
        self.url_port = conf.xget("api_pceReoptimizationByTunnel/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-lsp-reoptimization:lsp-reoptimization-cfg/pceReoptimizationBytunnel"
        self.method = "POST"

    def dotan(self, req=None):
        '''
        req: {
            "user-handle": "o:string",
            "auto-approve": "o:enum",
            "computation-priority": "o:int"
        }
        '''

        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, req, hdr)
        return 0 if status == 200 else -1, reason, res

class TunnelConfirm():
    ''' doc: 2.4.9 '''
    def __init__(self):
        self.url_scheme = conf.xget("api_lspStatistic/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_lspStatistic/url/hostname", def_hostname)
        self.url_port = conf.xget("api_lspStatistic/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-lsp-reoptimization:lsp-reoptimization-cfg/pceAprove"
        self.method = "POST"

    def dotan(self, req):
        userdata = req["args"]["user_data"]
        ci = req["args"]["user_data"]["create_info"]
        tunnel_name = ci["name"]
        approve = req["args"]["approve"]

        req = {"approve-result": "approve" if approve else 'disapprove'}

        hdr = token.todic()
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, req, hdr)
        if status != 200:
            return -1, "Set approve failed", None

        # 4. Get hop_list and check status to ensure the lsp is created successfully

        ret = DotDict()

        ret.name = ci["name"]
        ret.from_router_name = ci["from_router_name"]
        ret.from_router_uid = ci["from_router_uid"]
        ret.to_router_name = ci["to_router_name"]
        ret.to_router_uid = ci["to_router_uid"]
        ret.bandwidth = ci["bandwidth"]
        ret.delay = ci["delay"]
        ret.priority = ci["priority"]
        ret.user_data = userdata

        ret.uid = ci["uid"]
        # ret.path = ci["path"]
        ret.path = []

        ret.status = 0
        ret.hop_list = []

        err, msg, res = call(LspInfos)
        res = dmstr(res)
        for d in res.get("lsp-info", []):
            if d.get("tunnel-name") == tunnel_name:

                # Skip backup lsp
                role = d["lsp-role"]
                if role != "master":
                    continue

                # XXX: wake till it up?
                oper_state = d.get("oper-state")
                ret.status = 1 if oper_state == "operate-up" else 0

                # Fill the hop_list
                # for hop in d.hops.hop:
                for hop in d['hops']['hop']:
                    # klog.d("%s" % varfmt(hop, "hop in d.hops.hop"))
                    loopback = hop["lsr-id"]

                    e = einfo.fr_loopback(loopback)
                    if e:
                        # klog.d(varfmt(e, "equip"))
                        ret.hop_list.append(e.get("uid"))

                # Fill user_data and return
                # ret.user_data.status = ret.status
                ret['user_data']['status'] = ret['status']
                # ret.user_data.hop_list = ret.hop_list
                ret['user_data']['hop_list'] = ret['hop_list']

                return 0, "", ret

        return -1, "Error when lspInfo", None

class TunnelCreate():
    ''' doc: 2.3.1, name: ms_controller_add_lsp
    '''
    templ = '''
    {
        "tunnel-name": "AC-1.1.2.9Tunnel3",
        "tunnel-type": "te",
        "manage-protocol": "netconf",
        "control-mode": "delegate",
        "source": {
            "ne-id": "d056ee16-63da-4621-a210-740a72c6b468",
            "ip-address": "192.168.1.1"
        },
        "destination": {
            "ne-id": "bbf4f50c-32cd-4bfb-ade8-e803d4334af0",
            "ip-address": "192.168.1.2"
        },
        "path-setup-type": "rsvp-te",
    '''

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel"
        self.method = "POST"

    def dotan(self, req=None):
        klog.d("dotan")
        '''
        req: {
            "args": {
                "hop_list": [                                   <<
                    "PE11A",
                    "PE21A"
                ],
                "from_router_name": "",                         <<
                "to_router_name": "",                           <<
                "bandwidth": "",                                <<
                "to_router_uid": "",                            <<
                "from_router_uid": "",                          <<
                "callback": "http://127.0.0.1/path",            !!
                "name": "",                                     <<
                "priority": 7,                                  <<
                "delay": ""                                     <<

                "autoApprove": True                             <<
            },
            "request": "ms_controller_add_lsp",
            "ts": "20160718091442",
            "trans_id": 1468804482
        }

        resp: {
            "uid": "lsp_0",             !!
            "from_router_name": "",     <<
            "to_router_name": "",       <<
            "bandwidth": "",            <<
            "to_router_uid": "",        <<
            "from_router_uid": "",      <<
            "name": "",                 <<
            "hop_list": [],             <<
            "path": [],                 ??
            "status": 0,                !!
            "priority": 7,              <<
            "delay": "",                <<
            "user_data": {              !!
                "tunnel_name": "xxxxxxxxxxxx"
            }
        }
        '''
        varprt(req, color=True)
        args = DotDict(req["args"])

        def getloopback(router_uid):
            e = einfo.fr_uid(router_uid)
            return e.get("ip_str") if e else None

        def get_ne_id_fr_lsr_id(ne_info, lsrid):
            for ne in ne_info.ne:
                if ne["system"]["lsr-id"] == lsrid:
                    return ne["id"]
            return {}

        def get_ep_fr_router_uid(ne_info, router_uid):
            lsr_id = getloopback(router_uid)
            if not lsr_id:
                klog.e("dotan")
                return None, None

            ne_id = get_ne_id_fr_lsr_id(ne_info, lsr_id)
            if not ne_id:
                klog.e("dotan")
                return None, None

            return lsr_id, ne_id


        err, msg, res = call(NeOper_All)
        if err:
            err, msg, res = call(NeCfg_All)

        if err:
            klog.e("dotan")
            return -1, "Get NE Information failed", None
        ne_info = dmstr(res)

        fr_ip, fr_neid = get_ep_fr_router_uid(ne_info, args.get("from_router_uid"))
        if not fr_ip or not fr_neid:
            klog.e("dotan")
            return -1, "Collect NE information failed from_router_name", None

        to_ip, to_neid = get_ep_fr_router_uid(ne_info, args.get("to_router_uid"))
        if not to_ip or not to_neid:
            klog.e("dotan")
            return -1, "Collect NE information failed to_router_name", None

        hdr = token.todic()

        tunnel_name = args.get("name")

        # 1. Fill the parameter will be sent to web service
        dic = DotDict()
        dic["tunnel-name"] = tunnel_name
        dic["tunnel-type"] = "te"
        dic["manage-protocol"] = "netconf"
        dic["control-mode"] = "delegate"
        dic["path-setup-type"] = "rsvp-te"

        dic["source"] = {
            "ne-id": fr_neid,
            "ip-address": fr_ip
        }
        dic["destination"] = {
            "ne-id": to_neid,
            "ip-address": to_ip
        }

        varprt(hdr, "HDR")
        varprt(dic, "DIC")
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, dic, hdr)
        klog.d("status:%s" % status)
        if status != 201:
            klog.e("status is %d, 201 is expected" % status)
            return -1, reason, None

        newlsp = dmstr(res)

        # 2. ensure approve (doc: 2.4.4) by PceReoptimizationByTunnel
        autoApprove = args.get("autoApprove", "false")
        req = {
            "auto-approve": "true" if autoApprove == "true" else "false",
            "reoptimization-by-tunnelname": {
                "tunnel-name": tunnel_name
            }
        }

        req = {
            # "user-handle": "00000000-0000-0000-0000-000000000000",
            "auto-approve": "true" if autoApprove == "true" else "false",
            "computation-priority": "1000",
            "reoptimization-by-tunnelname": [
                {
                    "tunnel-name": tunnel_name
                }
            ]
        }

        err, msg, res = call(PceReoptimizationByTunnel, req)
        klog.d(varfmt(res, "PceReoptimizationByTunnel", True))

        if not res:
            return -1, "Set approve failed", None

        # 3. prepare the return value
        ret = DotDict()

        ret.name = args.name
        ret.from_router_name = args.from_router_name
        ret.from_router_uid = args.from_router_uid
        ret.to_router_name = args.to_router_name
        ret.to_router_uid = args.to_router_uid
        ret.bandwidth = args.bandwidth
        ret.delay = args.delay
        ret.priority = args.priority

        ret.uid = args.uid
        ret.path = []               # FIXME?
        ret.status = 0
        ret.hop_list = []           # FIXME: Should overwrite by returned information?

        if autoApprove == 'false':
            # 2.4.8
            err, msg, res = call(LspConfirm)
            res = dmstr(res)
            try:
                lsp_info = res["lsp-infos"]["lsp-info"]
            except:
                return -1, "", None

            for d in lsp_info:
                try:
                    ingress = d["ingress"]
                    egress = d["egress"]
                except:
                    continue

                if fr_ip == ingress and to_ip == egress:
                    # Skip backup lsp
                    role = d["lsp-role"]
                    if role != "master":
                        continue

                    # XXX: wake till it up?
                    oper_state = d.get("oper-state")
                    ret.status = 1 if oper_state == "operate-up" else 0

                    # Fill the hop_list
                    # for hop in d.hops.hop:
                    for hop in d['hops']['hop']:
                        # klog.d("%s" % varfmt(hop, "hop in d.hops.hop"))
                        loopback = hop["lsr-id"]

                        e = einfo.fr_loopback(loopback)
                        if e:
                            # klog.d(varfmt(e, "equip"))
                            ret.hop_list.append(e.get("uid"))
                        else:
                            klog.e("No equip found for loopback: ",  loopback)

                    # Fill user_data and return
                    ret.user_data.create_info = args
                    ret.user_data.tunnel_name = tunnel_name
                    ret.user_data.path = ret.path
                    ret.user_data.status = ret.status
                    ret.user_data.hop_list = ret.hop_list

                    ret.user_data.from_router_uid = args.from_router_uid

                    return 0, "", ret
            return -1, "", None
        else:
            # 4. Get hop_list and check status to ensure the lsp is created successfully
            start = time.time()
            while True:
                if time.time() - start > 30:
                    break

                err, msg, res = call(LspInfos)
                res = dmstr(res)
                for d in res.get("lsp-info", []):
                    if d.get("tunnel-name") == tunnel_name:

                        # Skip backup lsp
                        role = d["lsp-role"]
                        if role != "master":
                            continue

                        # XXX: wake till it up?
                        oper_state = d.get("oper-state")
                        ret.status = 1 if oper_state == "operate-up" else 0

                        # Fill the hop_list
                        # for hop in d.hops.hop:
                        for hop in d['hops']['hop']:
                            # klog.d("%s" % varfmt(hop, "hop in d.hops.hop"))
                            loopback = hop["lsr-id"]

                            e = einfo.fr_loopback(loopback)
                            if e:
                                # klog.d(varfmt(e, "equip"))
                                ret.hop_list.append(e.get("uid"))

                        # Fill user_data and return
                        ret.user_data.create_info = args
                        ret.user_data.tunnel_name = tunnel_name
                        ret.user_data.path = ret.path
                        ret.user_data.status = ret.status
                        ret.user_data.hop_list = ret.hop_list

                        ret.user_data.from_router_uid = args.from_router_uid

                        return 0, "", ret

                time.sleep(0.5)

        # 4. Return
        return -1, "Timeout when waiting operation", None

class TunnelCreate_AC():
    ''' doc: 2.3.1, name: ms_controller_add_lsp
    '''
    templ = '''
    {
        "tunnel-name": "AC-1.1.2.9Tunnel3",
        "tunnel-type": "te",
        "manage-protocol": "netconf",
        "control-mode": "delegate",
        "source": {
            "ne-id": "d056ee16-63da-4621-a210-740a72c6b468",
            "ip-address": "192.168.1.1"
        },
        "destination": {
            "ne-id": "bbf4f50c-32cd-4bfb-ade8-e803d4334af0",
            "ip-address": "192.168.1.2"
        },
        "path-setup-type": "rsvp-te",
    '''

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel"
        self.method = "POST"

    def dotan(self, req=None):
        klog.d("dotan")
        '''
        req: {
            "args": {
                "hop_list": [                                   <<
                    "PE11A",
                    "PE21A"
                ],
                "from_router_name": "",                         <<
                "to_router_name": "",                           <<
                "bandwidth": "",                                <<
                "to_router_uid": "",                            <<
                "from_router_uid": "",                          <<
                "callback": "http://127.0.0.1/path",            !!
                "name": "",                                     <<
                "priority": 7,                                  <<
                "delay": ""                                     <<

                "autoApprove": True                             <<
            },
            "request": "ms_controller_add_lsp",
            "ts": "20160718091442",
            "trans_id": 1468804482
        }

        resp: {
            "uid": "lsp_0",             !!
            "from_router_name": "",     <<
            "to_router_name": "",       <<
            "bandwidth": "",            <<
            "to_router_uid": "",        <<
            "from_router_uid": "",      <<
            "name": "",                 <<
            "hop_list": [],             <<
            "path": [],                 ??
            "status": 0,                !!
            "priority": 7,              <<
            "delay": "",                <<
            "user_data": {              !!
                "tunnel_name": "xxxxxxxxxxxx"
            }
        }
        '''
        varprt(req, color=True)
        args = DotDict(req["args"])

        def getloopback(router_uid):
            e = einfo.fr_uid(router_uid)
            return e.get("ip_str") if e else None

        def get_ne_id_fr_lsr_id(ne_info, lsrid):
            for ne in ne_info.ne:
                if ne["system"]["lsr-id"] == lsrid:
                    return ne["id"]
            return {}

        def get_ep_fr_router_uid(ne_info, router_uid):
            lsr_id = getloopback(router_uid)
            if not lsr_id:
                klog.e("dotan")
                return None, None

            ne_id = get_ne_id_fr_lsr_id(ne_info, lsr_id)
            if not ne_id:
                klog.e("dotan")
                return None, None

            return lsr_id, ne_id


        err, msg, res = call(NeOper_All)
        if err:
            err, msg, res = call(NeCfg_All)

        if err:
            klog.e("dotan")
            return -1, "Get NE Information failed", None
        ne_info = dmstr(res)

        fr_ip, fr_neid = get_ep_fr_router_uid(ne_info, args.get("from_router_uid"))
        if not fr_ip or not fr_neid:
            klog.e("dotan")
            return -1, "Collect NE information failed from_router_name", None

        to_ip, to_neid = get_ep_fr_router_uid(ne_info, args.get("to_router_uid"))
        if not to_ip or not to_neid:
            klog.e("dotan")
            return -1, "Collect NE information failed to_router_name", None

        hdr = token.todic()

        tunnel_name = args.get("name")

        # 1. Fill the parameter will be sent to web service
        dic = DotDict()
        dic["tunnel-name"] = tunnel_name
        dic["tunnel-type"] = "te"
        dic["manage-protocol"] = "netconf"
        dic["control-mode"] = "delegate"
        dic["path-setup-type"] = "rsvp-te"

        dic["source"] = {
            "ne-id": fr_neid,
            "ip-address": fr_ip
        }
        dic["destination"] = {
            "ne-id": to_neid,
            "ip-address": to_ip
        }

        varprt(hdr, "HDR")
        varprt(dic, "DIC")
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, dic, hdr)
        klog.d("status:%s" % status)
        if status != 201:
            klog.e("status is %d, 201 is expected, create tunnel fail" % status)
            return -1, reason, None

        # 3. prepare the return value
        ret = DotDict()

        ret.name = args.name
        ret.from_router_name = args.from_router_name
        ret.from_router_uid = args.from_router_uid
        ret.to_router_name = args.to_router_name
        ret.to_router_uid = args.to_router_uid
        ret.bandwidth = args.bandwidth
        ret.delay = args.delay
        ret.priority = args.priority
        return 0, "", ret

class TunnelCreate_netconf():
    ''' doc: 2.3.1, name: ms_controller_add_lsp
    '''
    templ = '''
    {
        "tunnel-name": "AC-1.1.2.9Tunnel3",
        "tunnel-type": "te",
        "manage-protocol": "netconf",
        "control-mode": "delegate",
        "source": {
            "ne-id": "d056ee16-63da-4621-a210-740a72c6b468",
            "ip-address": "192.168.1.1"
        },
        "destination": {
            "ne-id": "bbf4f50c-32cd-4bfb-ade8-e803d4334af0",
            "ip-address": "192.168.1.2"
        },
        "path-setup-type": "rsvp-te",
    '''

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel"
        self.method = "POST"

    def dotan(self, req=None):
        klog.d("dotan")
        '''
        req: {
            "args": {
                "hop_list": [                                   <<
                    "PE11A",
                    "PE21A"
                ],
                "from_router_name": "",                         <<
                "to_router_name": "",                           <<
                "bandwidth": "",                                <<
                "to_router_uid": "",                            <<
                "from_router_uid": "",                          <<
                "callback": "http://127.0.0.1/path",            !!
                "name": "",                                     <<
                "priority": 7,                                  <<
                "delay": ""                                     <<

                "autoApprove": True                             <<
            },
            "request": "ms_controller_add_lsp",
            "ts": "20160718091442",
            "trans_id": 1468804482
        }

        resp: {
            "uid": "lsp_0",             !!
            "from_router_name": "",     <<
            "to_router_name": "",       <<
            "bandwidth": "",            <<
            "to_router_uid": "",        <<
            "from_router_uid": "",      <<
            "name": "",                 <<
            "hop_list": [],             <<
            "path": [],                 ??
            "status": 0,                !!
            "priority": 7,              <<
            "delay": "",                <<
            "user_data": {              !!
                "tunnel_name": "xxxxxxxxxxxx"
            }
        }
        '''
        varprt(req, color=True)
        args = DotDict(req["args"])

        # ne model checker,
        if('from_router_uid' in args):
            ne_model = einfo.map_uid_obj[args['from_router_uid']]['model']
            pass
        elif('user_data' in req['args']):
            ne_model = einfo.map_uid_obj[args['user_data']['from_router_uid']]['model']
            pass
        # if (ne_model == 'NE40E'):
        #     return call(TunnelCreate_AC, req)

        def getloopback(router_uid):
            e = einfo.fr_uid(router_uid)
            return e.get("ip_str") if e else None

        def get_ne_id_fr_lsr_id(ne_info, lsrid):
            for ne in ne_info.ne:
                if ne["system"]["lsr-id"] == lsrid:
                    return ne["id"]
            return {}

        def get_ep_fr_router_uid(ne_info, router_uid):
            lsr_id = getloopback(router_uid)
            if not lsr_id:
                klog.e("dotan")
                return None, None

            ne_id = get_ne_id_fr_lsr_id(ne_info, lsr_id)
            if not ne_id:
                klog.e("dotan")
                return None, None

            return lsr_id, ne_id


        err, msg, res = call(NeOper_All)
        if err:
            err, msg, res = call(NeCfg_All)

        if err:
            klog.e("dotan")
            return -1, "Get NE Information failed", None
        ne_info = dmstr(res)

        fr_ip, fr_neid = get_ep_fr_router_uid(ne_info, args.get("from_router_uid"))
        if not fr_ip or not fr_neid:
            klog.e("dotan")
            return -1, "Collect NE information failed from_router_name", None

        to_ip, to_neid = get_ep_fr_router_uid(ne_info, args.get("to_router_uid"))
        if not to_ip or not to_neid:
            klog.e("dotan")
            return -1, "Collect NE information failed to_router_name", None

        hdr = token.todic()

        tunnel_name = args.get("name")

        # {u'hop_list': [], u'priority': 7, u'name': u'311', u'from_router_name': u'', u'to_router_name': u'', u'autoApprove': u'false', u'delay': u'', u'callback': u'http://127.0.0.1/path', u'bandwidth': u'1000', u'to_router_uid': u'3', u'from_router_uid': u'1'}
        '''
        {"args":
            {
            "hop_list": ["3", "1"],
            "name": "113",
            "from_router_name": "Shanghai",
            "to_router_name": "Nanjing",
            "priority": 7,
            "callback": "lsp_man_cb_lsp",
            "bandwidth": 100,
            "to_router_uid": "1",
            "from_router_uid": "3",
            "uid": "248",
            "includeAny":"0x01",
            "excludeAny":"0x02"
            },
            "request": "ms_controller_add_lsp",
            "ts": "20161216142607",
            "trans_id": 1481869567
        }
        '''
        req_test = {}
        req_test['name'] = 'Tunnel' + args['name']
        req_test['to_router_uid'] = einfo.fr_uid(args['to_router_uid']).get("ip_str")
        req_test['from_router_uid'] = einfo.fr_uid(args['from_router_uid']).get("ip_str")
        req_test['uid'] = args['uid']
        req_test['bandwidth'] = args['bandwidth']
        req_test['priority'] = args['priority']
        # req_test['hop_list'] = args['hop_list']
        req_test['hop_list'] = []
        if args['hop_list'].__len__() > 2:
            for hop in args['hop_list']:
                if hop == args['from_router_uid']:
                    continue
                req_test['hop_list'].append(einfo.fr_uid(hop).get("ip_str"))
        req_test['includeAny'] = args['includeAny'] if 'includeAny' in args else ''
        req_test['excludeAny'] = args['excludeAny'] if 'excludeAny' in args else ''
        netconf_port = einfo.fr_netconf_port(req_test['from_router_uid'])
        hwnc = HW_NetConf(port=netconf_port, username = hw_netconf_user, password = hw_netconf_passwd if req_test['from_router_uid'] != '5.5.5.5' else hw_netconf_passwd_R5)
        status = hwnc.hw_create_tunnel_netconf(req_test)
        klog.d("status:%s" % status)
        if status != 0:
            klog.e("status is %d, create tunnel fail" % status)
            return -1, None, None

        # 3. prepare the return value
        ret = DotDict()

        ret.name = args.name
        ret.from_router_name = args.from_router_name
        ret.from_router_uid = args.from_router_uid
        ret.to_router_name = args.to_router_name
        ret.to_router_uid = args.to_router_uid
        ret.bandwidth = args.bandwidth
        ret.delay = args.delay
        ret.priority = args.priority
        return 0, "", ret

class TunnelDelete_AC():

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel/{tunnel_name}"
        self.method = "DELETE"

    def dotan(self, req=None):
        klog.d("dotan")
        varprt(req, color=True)
        args = DotDict(req["args"])
        hdr = token.todic()
        #"user_data": {"status": 1, "hop_list": ["2", "1", "3"], "to_router_uid": "3", "path": ["2", "1", "3"], "from_router_uid": "2", "tunnel_name": "111"}
        url_pathpat = self.url_pathpat.format(tunnel_name = args['user_data']["tunnel_name"])
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, url_pathpat, self.method, None, hdr)
        if status != 200:
            klog.e("status is %d, delete tunnel fail" % status)
            return -1, reason, None

        # 3. prepare the return value
        ret = DotDict()

        ret.name = args['user_data']["tunnel_name"]
        ret.user_data = args.user_data

        # 4. Return
        return 0, "delete tunnel ok", ret
    pass

class TunnelDelete_netconf():

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel"
        self.method = "POST"

    def dotan(self, req=None):
        klog.d("dotan")
        varprt(req, color=True)
        args = DotDict(req["args"])

        # ne model checker,
        if('from_router_uid' in args):
            ne_model = einfo.map_uid_obj[args['from_router_uid']]['model']
            pass
        elif('user_data' in req['args']):
            ne_model = einfo.map_uid_obj[args['user_data']['from_router_uid']]['model']
            pass
        # if (ne_model == 'NE40E'):
        #     return call(TunnelDelete_AC, req)


        hdr = token.todic()
        #"user_data": {"status": 1, "hop_list": ["2", "1", "3"], "to_router_uid": "3", "path": ["2", "1", "3"], "from_router_uid": "2", "tunnel_name": "111"}
        req_test = {}
        req_test['name'] = 'Tunnel' + args['user_data']["tunnel_name"]
        req_test['from_router_uid'] = einfo.fr_uid(args['user_data']['from_router_uid']).get("ip_str")
        req_test['hop_list'] = []
        if args['user_data']['hop_list'].__len__() > 2:
            for hop in args['user_data']['hop_list']:
                if hop == args['user_data']['from_router_uid']:
                    continue
                req_test['hop_list'].append(einfo.fr_uid(hop).get("ip_str"))

        #connect from_router_uid
        netconf_port = einfo.fr_netconf_port(req_test['from_router_uid'])
        hwnc_ = HW_NetConf(port=netconf_port, username = hw_netconf_user, password = hw_netconf_passwd if req_test['from_router_uid'] != '5.5.5.5' else hw_netconf_passwd_R5)
        status = hwnc_.hw_del_tunnel_netconf(req_test)
        klog.d("status:%s" % status)
        if status != 0:
            klog.e("status is %d, delete tunnel fail" % status)
            return -1, None, None

        # 3. prepare the return value
        ret = DotDict()

        ret.name = args['user_data']["tunnel_name"]
        ret.user_data = args.user_data

        # 4. Return
        return status, "delete tunnel ok", ret
    pass

class TunnelStatusCheck():
    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel"
        self.method = "POST"

    def dotan(self, req=None):
        klog.d("dotan TunnelStatusCheck")
        varprt(req, color=True)
        args = DotDict(req["args"])
        hdr = token.todic()
        tunnel_name = args.get("name")

        # 3. prepare the lsp item value
        result = {'lsps':[]}
        ret = DotDict()
        ret.name = args.name
        ret.from_router_name = args.from_router_name
        ret.from_router_uid = args.from_router_uid
        ret.to_router_name = args.to_router_name
        ret.to_router_uid = args.to_router_uid
        ret.bandwidth = args.bandwidth
        ret.delay = args.delay
        ret.priority = args.priority

        ret.uid = args.uid
        ret.path = []               # FIXME?
        ret.status = 0
        ret.hop_list = []           # FIXME: Should overwrite by returned information?

        # 4. Get hop_list and check status to ensure the lsp is created successfully
        err, msg, res = call(LspInfos)
        res = dmstr(res)
        for d in res.get("lsp-info", []):
            # if d.get("tunnel-name") == tunnel_name:
            if (d.get("sym-path-name") == ('Tunnel' + tunnel_name) and str(d.get("tunnel-id")) == str(args.uid)) or (d.get("tunnel-name") == tunnel_name):
                # Skip backup lsp
                role = d["lsp-role"]
                if role != "master":
                    continue

                # XXX: wake till it up?
                oper_state = d.get("oper-state")
                ret.status = 1 if oper_state == "operate-up" else -1

                # Fill the hop_list
                # for hop in d.hops.hop:
                if (d['hops']['hop'].__len__ > 0):
                    ret.hop_list.append(args.from_router_uid)
                    ret.path.append(args.from_router_uid)
                for hop in d['hops']['hop']:
                    if hop['hop-inc-type'] == 'outgoing':
                        continue
                    loopback = hop["lsr-id"]
                    e = einfo.fr_loopback(loopback)
                    if e:
                        # klog.d(varfmt(e, "equip"))
                        ret.hop_list.append(e.get("uid"))
                        ret.path.append(e.get("uid"))

                # Fill user_data and return
                # ret.user_data.create_info = args
                ret.user_data.tunnel_name = tunnel_name
                ret.user_data.path = ret.path
                ret.user_data.status = ret.status
                ret.user_data.hop_list = args.hop_list
                ret.user_data.from_router_uid = args.from_router_uid
                ret.user_data.to_router_uid = args.to_router_uid
                result['lsps'].append(ret)
        # 4. Return
        return 0, None, result

class AddRule2RedirectedTunnel():

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel"
        self.method = "POST"

    def dotan(self, req=None):
        klog.d("dotan")
        varprt(req, color=True)
        args = DotDict(req["args"])
        hdr = token.todic()
        #{"callback": "flow_sched_callback","lsp_uid": "235", "flow": {"src": "10.0.1.10/32", "dst": "10.0.11.10/32", "uid": "2"}, "user_data":{"status": 1, "hop_list": ["2", "1", "3"], "to_router_uid": "3", "path": ["2", "1", "3"], "from_router_uid": "2", "tunnel_name": "113"}
        req_test = {}
        req_test['tunnel_name'] = 'Tunnel' + args['user_data']["tunnel_name"]
        req_test['to_router_uid'] = einfo.fr_uid(args['user_data']['to_router_uid']).get("ip_str")
        req_test['from_router_uid'] = einfo.fr_uid(args['user_data']['from_router_uid']).get("ip_str")
        flow_uid = '1'
        if ('rule_id' in args):
            req_test['rule_id'] = args['rule_id']
        if ('flow' in args):
            if('src' in args['flow']):
                req_test['ipv4_src'] = args['flow']['src']
            if('dst' in args['flow']):
                req_test['ipv4_dst'] = args['flow']['dst']
            if ('uid' in args['flow']):
                flow_uid = args['flow']['uid']
        req_test['to_loopback_id'] = 'LoopBack' + flow_uid
        req_test['to_loopback_ip'] = num2ip(ip2num(req_test['to_router_uid']) + int(flow_uid))
        #connect from_router_uid
        netconf_port = einfo.fr_netconf_port(req_test['from_router_uid'])
        hwnc_ = HW_NetConf(port=netconf_port, username = hw_netconf_user, password = hw_netconf_passwd if req_test['from_router_uid'] != '5.5.5.5' else hw_netconf_passwd_R5)
        status = hwnc_.hw_add_rule_to_redirected_tunnel_netconf(req_test)
        klog.d("status:%s" % status)
        if status != 0:
            klog.e("status is %d, add rule fail" % status)
            return -1, None, None

        # 3. prepare the return value
        ret = DotDict()

        ret.name = args['user_data']["tunnel_name"]
        args['user_data']['flow_uid'] = args['flow']['uid']
        args['user_data']['to_loopback_id'] = req_test['to_loopback_id']
        args['user_data']['to_loopback_ip'] = req_test['to_loopback_ip']
        ret.user_data = args.user_data

        # 4. Return
        return status, "add rule ok", ret
    pass

class LinkConfig_netconf():

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel"
        self.method = "POST"

    def dotan(self, req=None):
        klog.d("dotan")
        varprt(req, color=True)
        args = DotDict(req["args"])
        req_test = {}
        req_test['to_router_uid'] = einfo.fr_uid(args['to_router_uid']).get("ip_str")
        req_test['from_router_uid'] = einfo.fr_uid(args['from_router_uid']).get("ip_str")
        req_test['intf'] = args['intf']
        req_test['link_property'] = args['link_property']
        #connect from_router_uid
        netconf_port = einfo.fr_netconf_port(req_test['from_router_uid'])
        # hwnc_ = HW_NetConf(port=netconf_port, username = hw_netconf_user, password = hw_netconf_passwd)
        hwnc_ = HW_NetConf(port=netconf_port, username = hw_netconf_user, password = hw_netconf_passwd if req_test['from_router_uid'] != '5.5.5.5' else hw_netconf_passwd_R5)
        status = hwnc_.hw_link_property_config_netconf(req_test)
        klog.d("status:%s" % status)
        if status != 0:
            klog.e("status is %d, LinkConfig_netconf fail" % status)
            return -1, None, None

        # 3. prepare the return value
        ret = DotDict()
        # 4. Return
        return status, "LinkConfig_netconf ok", ret
    pass

class LinkDelayConfig():

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-network-te-topology:l3-topology-cfg/topologies/topology/4acbd130-846b-3536-a142-8a42d8a3c4b8/links"
        self.method = "PUT"

    def dotan(self, req=None):
        klog.d("dotan")
        varprt(req, color=True)
        args = DotDict(req["args"])
        '''
        {
        "args": {
            "delay": "3",
            "from_router_uid": "1",
            "id": "3.3.3.3&10.230.10.1_1.1.1.1&10.230.10.2",
            "uid": "11"
        },
        "request": "ms_controller_set_vlink_delay"
        }
        '''
        if (not einfo.fr_link_ip_obj(args['id'])):
            err, msg, res = call(L3_Topo)
            if err or (not einfo.fr_link_ip_obj(args['id'])):
                return -1, "LinkDelayConfig failed", None
        update_req = {"link": []}
        sub_req = einfo.fr_link_ip_obj(args['id'])
        if ('te-attributes' in sub_req and 'latency' in sub_req['te-attributes']):
            sub_req['te-attributes']['latency'] = args['delay']
            update_req['link'].append(sub_req)
        # do req
        err, msg, res = call(L3_LinkCfg_Update, update_req)
        if err:
            return -1, "LinkDelayConfig failed", res
        # 3. prepare the return value
        # 4. Return
        return 0, "LinkDelayConfig ok", req
    pass

class RedirectToTunnel():

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel"
        self.method = "POST"

    def dotan(self, req=None):
        start = time.time()
        klog.d("dotan")
        varprt(req, color=True)
        args = DotDict(req["args"])
        hdr = token.todic()
        #{"callback": "flow_sched_callback","lsp_uid": "235", "flow": {"src": "10.0.1.10/32", "dst": "10.0.11.10/32", "uid": "2"}, "user_data":{"status": 1, "hop_list": ["2", "1", "3"], "to_router_uid": "3", "path": ["2", "1", "3"], "from_router_uid": "2", "tunnel_name": "113"}
        req_test = {}
        req_test['tunnel_name'] = 'Tunnel' + args['user_data']["tunnel_name"]
        req_test['to_router_uid'] = einfo.fr_uid(args['user_data']['to_router_uid']).get("ip_str")
        req_test['from_router_uid'] = einfo.fr_uid(args['user_data']['from_router_uid']).get("ip_str")
        flow_uid = '1'
        if ('flow' in args):
            # not match the flow src currently
            # if('src' in args['flow']):
            #     req_test['ipv4_src'] = args['flow']['src']
            if('dst' in args['flow']):
                req_test['ipv4_dst'] = args['flow']['dst']
            if ('uid' in args['flow']):
                flow_uid = args['flow']['uid']
        req_test['to_loopback_id'] = 'LoopBack' + flow_uid
        ip1 = num2ip(ip2num(req_test['to_router_uid']) + int(flow_uid))
        print(ip1)
        req_test['to_loopback_ip'] = num2ip(ip2num(req_test['to_router_uid']) + int(flow_uid))
        #connect to_router_uid
        netconf_port = einfo.fr_netconf_port(req_test['to_router_uid'])
        hwnc = HW_NetConf(port=netconf_port, username = hw_netconf_user, password = hw_netconf_passwd)
        status = hwnc.hw_create_intf_ip_netconf(req_test)
        klog.d("status:%s" % status)
        if status != 0:
            klog.e("status is %d, create to_router_id ip fail" % status)
            return -1, None, None

        #connect from_router_uid
        netconf_port = einfo.fr_netconf_port(req_test['from_router_uid'])
        # hwnc_ = HW_NetConf(port=netconf_port, username = hw_netconf_user, password = hw_netconf_passwd)
        hwnc_ = HW_NetConf(port=netconf_port, username = hw_netconf_user, password = hw_netconf_passwd if req_test['from_router_uid'] != '5.5.5.5' else hw_netconf_passwd_R5)
        status = hwnc_.hw_redirect_to_tunnel_netconf(req_test)
        # for testing max num of redirected flow
        # spent time is 28600.7610002 s
        # status = hwnc_.hw_redirect_to_tunnel_max_nums_netconf(req_test)
        klog.d("status:%s" % status)
        if status != 0:
            klog.e("status is %d, redirect flow to tunnel fail" % status)
            return -1, None, None

        # 3. prepare the return value
        ret = DotDict()

        ret.name = args['user_data']["tunnel_name"]
        args['user_data']['flow_uid'] = args['flow']['uid']
        args['user_data']['to_loopback_id'] = req_test['to_loopback_id']
        args['user_data']['to_loopback_ip'] = req_test['to_loopback_ip']
        ret.user_data = args.user_data
        print('spent time is ' + str(time.time() - start) + ' s')
        # 4. Return
        return status, "redirect flow to tunnel ok", ret
    pass

class UndoRedirectToTunnel():

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel"
        self.method = "POST"

    def dotan(self, req=None):
        klog.d("dotan")
        varprt(req, color=True)
        args = DotDict(req["args"])
        hdr = token.todic()
        #{"callback": "flow_sched_callback","lsp_uid": "235", "flow": {"src": "10.0.1.10/32", "dst": "10.0.11.10/32", "uid": "2"}, "user_data":{"status": 1, "hop_list": ["2", "1", "3"], "to_router_uid": "3", "path": ["2", "1", "3"], "from_router_uid": "2", "tunnel_name": "113"}
        req_test = {}
        req_test['tunnel_name'] = 'Tunnel' + args['user_data']["tunnel_name"]
        req_test['to_router_uid'] = einfo.fr_uid(args['user_data']['to_router_uid']).get("ip_str")
        req_test['from_router_uid'] = einfo.fr_uid(args['user_data']['from_router_uid']).get("ip_str")
        req_test['to_loopback_id'] = args['user_data']['to_loopback_id']
        req_test['to_loopback_ip'] = args['user_data']['to_loopback_ip']
        #connect to_router_uid
        netconf_port = einfo.fr_netconf_port(req_test['to_router_uid'])
        hwnc = HW_NetConf(port=netconf_port, username = hw_netconf_user, password = hw_netconf_passwd)
        status = hwnc.hw_del_intf_ip_netconf(req_test)
        klog.d("status:%s" % status)
        if status != 0:
            klog.e("status is %d, UndoRedirectToTunnel fail" % status)
            return -1, None, None

        #connect from_router_uid
        netconf_port = einfo.fr_netconf_port(req_test['from_router_uid'])
        # hwnc_ = HW_NetConf(port=netconf_port, username = hw_netconf_user, password = hw_netconf_passwd)
        hwnc_ = HW_NetConf(port=netconf_port, username = hw_netconf_user, password = hw_netconf_passwd if req_test['from_router_uid'] != '5.5.5.5' else hw_netconf_passwd_R5)
        status = hwnc_.hw_undo_redirect_to_tunnel_netconf(req_test)
        klog.d("status:%s" % status)
        if status != 0:
            klog.e("status is %d, undo redirect flow to tunnel fail" % status)
            return -1, None, None

        # 3. prepare the return value
        ret = DotDict()

        ret.name = args['user_data']["tunnel_name"]
        args['user_data']['to_loopback_id'] = req_test['to_loopback_id']
        args['user_data']['to_loopback_ip'] = req_test['to_loopback_ip']
        ret.user_data = args.user_data

        # 4. Return
        return status, "undo redirect flow to tunnel ok", ret
    pass

class RedirectToTunnelStatusCheck():

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelCreate/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelCreate/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelCreate/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel"
        self.method = "POST"

    def dotan(self, req=None):
        klog.d("dotan")
        varprt(req, color=True)
        args = DotDict(req["args"])
        hdr = token.todic()
        ret = DotDict()

        ret.name = args.lspname
        ret.user_data = args.user_data
        # 4. Return
        return 0, "redirect flow to tunnel ok", ret
    pass

################################################
class TunnelModify():
    '''ms_controller_update_lsp

    FIXME: Not defined yet

    NOTE: The parameter is same as TunnelCreate
    '''

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelModify/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelModify/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelModify/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel"
        self.method = "PUT"

    def dotan(self, req=None):
        '''
        Only update the bandwidth

        req: {
            "uid": "46",
            "user_data": {
                "tunnel_name": "xxxxxxxxxxxx"
            },
            "callback": "http://127.0.0.1/path",
            "bandwidth": ""
        }

        resp: None
        '''

        # req.user_data.tunnelName => lspInfo => dic => dic.bandwidth = req.bandwidth => hget

        args = req["args"]

        tunnel_name = args.user_data.tunnel_name
        err, msg, res = call(TunnelQueryInstance, tunnel_name)

        dic = DotDict()
        dic["tunnel-name"] = res["tunnel-name"]
        dic["tunnel-type"] = inof["tunnel-type"]
        dic["manage-protocol"] = inof["manage-protocol"]
        dic["control-mode"] = inof["control-mode"]
        dic["path-setup-type"] = inof["path-setup-type"]
        dic["source"] = inof["source"]
        dic["destination"] = inof["destination"]
        dic["tunnel-constraint"]["bandwidth"] = args.bandwidth

        hdr = token.todic()

        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, dic, hdr)
        return 0 if status == 200 else -1, reason, res

################################################

class TunnelConstrait():
    '''FIXME: Not yet
    '''

    templ = '''
    {
        "tunnel-name": "string",
        "oper-bandwidth": "int"
    }
    '''

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelConstrait/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelConstrait/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelConstrait/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel/{tunnel_name}/tunnel-constraint"
        self.method = "PUT"

    def dotan(self, tunnel_name, oper_bandwidth):
        hdr = token.todic()

        dic = {"tunnel-name": tunnel_name, "oper-bandwidth": oper_bandwidth}

        url_pathpat = self.url_pathpat.format(tunnel_name=tunnel_name)
        status, reason, resp = hget(self.url_scheme, self.url_hostname, self.url_port, url_pathpat, self.method, dic, hdr)
        return 0 if status == 200 else -1, reason, resp

################################################

class TunnelDelete():
    '''ms_controller_del_lsp

    FIXME: Not defined in doc
    '''
    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelDelete/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelDelete/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelDelete/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel/{tunnel_name}"
        self.method = "DELETE"

    def dotan(self, req=None):
        '''
        req: {
            "uid": "46",
            "user_data": {
                "tunnel_name": "xxxxxxxxxxxx"
                "path": "xxxxxxxxxxxx",
                "status": "xxxxxxxxxxxx",
                "hop_list": ["this", "is", "real", "hops"],
                "create_info": {
                    "uid": xxx,
                    "from_router_name": xxx,
                    "hop_list": ["this", 'is', 'set', 'hoplist'],
                    "...": "...",
                }
            },
            "callback": "http://127.0.0.1/path"
        }

        resp: {
            "uid": "lsp_0",
            "from_router_name": "",
            "to_router_name": "",
            "bandwidth": "",
            "to_router_uid": "",
            "from_router_uid": "",
            "name": "",
            "hop_list": [],
            "path": [],
            "status": 0,
            "priority": 7,
            "delay": "",
            "user_data": {}
        }
        '''

        userdata = req["args"]["user_data"]
        ci = req["args"]["user_data"]["create_info"]

        klog.d(varfmt(ci, "create_info"))
        tunnel_name = ci["name"]

        hdr = token.todic()

        url_pathpat = self.url_pathpat.format(tunnel_name=tunnel_name)
        status, reason, resp = hget(self.url_scheme, self.url_hostname, self.url_port, url_pathpat, self.method, None, hdr)
        if status != 200:
            return -1, reason, None

        resp = {
            "uid": ci.get("uid"),
            "from_router_name": ci.get("from_router_name"),
            "to_router_name": ci.get("to_router_name"),
            "bandwidth": ci.get("bandwidth"),
            "to_router_uid": ci.get("to_router_uid"),
            "from_router_uid": ci.get("from_router_uid"),
            "name": ci.get("name"),
            "hop_list": ci.get("hop_list"),
            "path": userdata.get("path"),
            "status": userdata.get("status"),
            "priority": ci.get("priority"),
            "delay": ci.get("delay"),
            "user_data": userdata,
        }

        return 0, "", resp

################################################

class TunnelQueryInstance():
    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelQueryInstance/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelQueryInstance/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelQueryInstance/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel/{tunnel_name}"
        self.method = "GET"

    def dotan(self, tunnel_name):
        hdr = token.todic()

        url_pathpat = self.url_pathpat.format(tunnel_name=tunnel_name)
        status, reason, resp = hget(self.url_scheme, self.url_hostname, self.url_port, url_pathpat, self.method, None, hdr)
        return 0 if status == 200 else -1, reason, resp

################################################

class TunnelQueryList():
    templ = '''
    {
        "src-ne-id":"1.1.1.1",
        "dst-ne-id":"2.2.2.2",
        "tunnel-name":""
    }
    '''

    def __init__(self):
        self.url_scheme = conf.xget("api_tunnelQueryList/url/scheme", def_scheme)
        self.url_hostname = conf.xget("api_tunnelQueryList/url/hostname", def_hostname)
        self.url_port = conf.xget("api_tunnelQueryList/url/port", def_port)
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/query-te-tunnels-nbi"
        self.method = "POST"

    def dotan(self, req=None):
        hdr = token.todic()

        dic = dmstr(self.templ)
        dic.update(req)

        status, reason, resp = hget(self.url_scheme, self.url_hostname, self.url_port, self.url_pathpat, self.method, dic, hdr)
        return 0 if status == 200 else -1, reason, resp

class TunnelQuery():
    def __init__(self):
        klog.d("a")
        pass

    def dotan(self, req=None):
        '''
        req: {
            "uid": "46",
            "user_data": {
                "tunnel_name": "xxxxxxxxxxxx"
                "path": "xxxxxxxxxxxx",
                "status": "xxxxxxxxxxxx",
                "hop_list": ["this", "is", "real", "hops"],
                "create_info": {
                    "uid": xxx,
                    "from_router_name": xxx,
                    "hop_list": ["this", 'is', 'set', 'hoplist'],
                    "...": "...",
                }
            }
        }

        resp: [
            {
                "uid": "lsp_0",
                "from_router_name": "",
                "to_router_name": "",
                "bandwidth": "",
                "to_router_uid": "",
                "from_router_uid": "",
                "name": "",
                "hop_list": [],
                "path": [],
                "status": 0,
                "priority": 7,
                "delay": "",
                "user_data": {}
            }
        ]
        '''
        ret = {"lsps": []}
        if ('user_data' in req['args']):
            userdata = req["args"]["user_data"]
            ci = req["args"]["user_data"]["create_info"]
            tunnel_name = ci["name"]

            status = userdata["status"]
            hop_list = []

            err, msg, res = call(LspInfos)
            res = dmstr(res)
            for d in res.get("lsp-info", []):
                if d.get("tunnel-name") == tunnel_name:

                    # Skip backup lsp
                    role = d["lsp-role"]
                    if role != "master":
                        continue

                    # XXX: wake till it up?
                    oper_state = d.get("oper-state")
                    status = 1 if oper_state == "operate-up" else 0

                    # Fill the hop_list
                    # for hop in d.hops.hop:
                    for hop in d['hops']['hop']:
                        loopback = hop["lsr-id"]

                        e = einfo.fr_loopback(loopback)
                        if e:
                            hop_list.append(e.get("uid"))

                    break

            resp = {
                "uid": ci["uid"],
                "from_router_name": ci["from_router_name"],
                "to_router_name": ci["to_router_name"],
                "bandwidth": ci["bandwidth"],
                "to_router_uid": ci["to_router_uid"],
                "from_router_uid": ci["from_router_uid"],
                "name": ci["name"],
                "hop_list": hop_list or ci["hop_list"],
                "path": userdata["path"],
                "status": status or userdata["status"],
                "priority": ci["priority"],
                "delay": ci["delay"],
                "user_data": userdata,
            }
            ret['lsps'].append(resp)
        else:
            err, msg, res = call(LspInfos)
            res = dmstr(res)
            for d in res.get("lsp-info", []):
                ret['lsps'].append(d)
            pass
        return 0, "", ret

### #####################################################################
## MS Interface
#
def MSIF_TunnelCreate():
    pass


### #####################################################################
## mcon etc
#
import platform
if platform.system() == "Linux":
    from roar.roar import CallManager, CmdServer_Socket

    callman = CallManager()
    cmdserv = CmdServer_Socket(callman, 55000)
    cmdserv.start()

    @callman.deccmd()
    def tok(cmdctx, calldic):
        return token.todic()

    @callman.deccmd()
    def tunnelCreate(cmdctx, calldic):
        return call(NeOper_All)

    @callman.deccmd()
    def LspInfos_(cmdctx, calldic):
        return call(LspInfos)

    @callman.deccmd()
    def ddd(cmdctx, calldic):
        '''TunnelDelete tunnelName'''

        tunnel = calldic.get_args()[0]

        r = DotDict()
        r.args.user_data.create_info.name = tunnel
        return call(TunnelDelete, r)

    @callman.deccmd()
    def ccc(cmdctx, calldic):
        '''Trace issue of tunnelCreate'''
        req = '''
        {
            "args": {
                "hop_list": [],
                "from_router_name": "",
                "to_router_name": "",
                "bandwidth": "1000",
                "to_router_uid": "UID_HUAWEI_5_5_5_5",
                "from_router_uid": "UID_HUAWEI_1_1_1_1",
                "callback": "http://127.0.0.1/path",
                "name": "tunnel_hw_1_5",
                "priority": 7,
                "delay": "",
                "autoApprove": "true"
            },
            "request": "ms_controller_add_lsp",
            "ts": "20160718091442",
            "trans_id": 1468804482
        }
        '''

        req = dmstr(req)
        varprt(req)
        return call(tunnelCreate, req)

### #####################################################################
## web service
#

from bottle import get, post, put, delete, run, request
def idic():
    try:
        payload = request.body.read() or "{}"
        dic = dmstr(payload)
        return dic
    except:
        traceback.print_exc()
        return DotDict()


def odic(indic):
    odic = DotDict()

    odic.response = indic.request
    odic.trans_id = indic.trans_id
    odic.ts = time.strftime("%Y%m%d%H%M%S")

    odic.result = DotDict()

    odic.err_code = 0
    odic.msg = None

    return odic


@post("/api/<cls>")
def callService(cls):
    calldic = idic()
    klog.d(varfmt(calldic))

    cls = globals()[cls]
    if calldic.args:
        err, msg, res = call(cls, calldic)
    else:
        err, msg, res = call(cls)

    klog.d(varfmt(res, "RES"))

    respdic = odic(calldic)
    return json.dumps(respdic)



if 0:
    print
    print
    print
    print "TunnelConstrait....................................."
    req = {"tunnel-name":"AC_1.1.1.1Tunnel11", "oper-bandwidth": 3423423452}
    call(TunnelConstrait, req)

if 0:
    print
    print
    print
    print "TunnelDelete....................................."
    req = {"tunnel-name":"AC_1.1.1.1Tunnel11___", "oper-bandwidth": 3423423452}
    call(TunnelDelete, req)

if 0:
    print
    print
    print
    print "NeCfg_All....................................."
    ne_cfg_all = call(NeCfg_All)

if 0:
    print
    print
    print
    print "NeCfg_One....................................."
    call(NeCfg_One, "5979bc87-bf16-4260-9391-e1b0b1bbbaca")


if 0:
    print
    print
    print
    print "NeOper_All....................................."
    x = NeOper_All()
    ne_oper_all = x.dotan()


if 0:
    ne_oper_all = call(NeOper_All)

if 0:
    os._exit(0)

def bottleServ(cookie):
    run(server='paste', host='0.0.0.0', port=10001, debug=True)


# import deferdo
# deferdo.DeferDo(bottleServ)

if __name__ == "__main__":
    sys.path.append(miedir + "/..")
    import ms_controller as msc
    run(server='paste', host='0.0.0.0', port=10001, debug=True)


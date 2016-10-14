#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Copyright 2016 China Telecommunication Co., Ltd.
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

import traceback
import time
import dotmap
import httplib
import ssl
import json
import datetime

from bprint import varprt, varfmt
from xlogger import *

__author__ = 'kamasamikon'

klog.d("Loading %s ..." % __file__)

### #####################################################################
## Helper
#

def dmstr(dat):
    '''DotMap from a String'''

    try:
        dic = json.JSONDecoder().decode(str(dat))
    except:
        dic = {}
    return dotmap.DotMap(dic)


def dmdic(dic):
    '''DotMap from a Dict'''

    return dotmap.DotMap(dic)


def hget(scheme, hostname, port, path, method="GET", dat=None, hdr=None, timeout=None):
    '''Http get'''

    hdr = hdr or {}

    if scheme == "https":
        context = ssl._create_unverified_context()
        hc = httplib.HTTPSConnection(hostname, port, timeout, context=context)
    else:
        hc = httplib.HTTPConnection(hostname, port, timeout)

    params = json.dumps(dat)
    hc.request(method, path, params, hdr)
    r = hc.getresponse()
    dat = r.read()

    klog.d()
    klog.d("+" * 30)
    klog.d("METHOD : %s" % method)
    klog.d("STATUS : %d" % r.status)
    klog.d("REASON : %s" % r.reason)
    klog.d("  PATH : %s" % path)
    klog.d(varfmt(dmstr(dat).toDict(), "DUMP HGET DATA"))
    klog.d("-" * 30)
    klog.d()

    return r.status, r.reason, dat


def hgetx(obj, method="GET", dat=None, hdr=None, timeout=None):
    '''hget ext'''

    return hget(obj.url_scheme, obj.url_hostname, obj.url_port, obj.url_pathpat, method, dat, hdr, timeout)


def call(cls, *args, **kwargs):
    return cls().dotan(*args, **kwargs)

### #####################################################################
## Token
#
class TokenGetter():
    def __init__(self):
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_port = 8182
        self.url_pathpat = "/controller/v2/tokens"

        self.token_str = None
        self.expired_time = 0

        self.username = "kamasamikon@qq.com"
        self.userpass = "auv@3721.com"

    def _parsetime(self, timestr):
        # 2016-10-12T02:17:47,960+08:00

        x = timestr.split(',')[0]
        d = x.replace("T", "").replace(":", "").replace("-", "")
        return int(d)

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
        userinfo = {"userName": self.username, "password": self.userpass}
        status, reason, resp = hgetx(self, "POST", userinfo)
        dic = dmstr(resp)

        try:
            data = dic["data"]
            self.token_str = data["token_id"]
            self.expired_time = self._parsetime(data["expiredDate"])
        except:
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
    def __init__(self, map_uid_obj=None, map_loopback_uid=None):
        self.set_map(map_uid_obj, map_loopback_uid)

    def set_map(self, map_uid_obj=None, map_loopback_uid=None):
        self.map_uid_obj = map_uid_obj or {}
        self.map_loopback_uid = map_loopback_uid or {}

    def fr_uid(self, uid):
        return self.map_uid_obj.get(uid)

    def fr_loopback(self, loopback):
        uid = self.map_loopback_uid.get(loopback)
        return self.fr_uid(uid)

einfo = EquipInfo()


### #####################################################################
## Apis
#
class NeCfg_All():
    ''' doc: 2.1.1 '''
    def __init__(self):
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_port = 8182
        self.url_pathpat = "/restconf/config/huawei-ac-inventory:inventory-cfg/nes"
        self.method = "GET"

    def dotan(self):
        hdr = token.todic()
        status, reason, res = hgetx(self, self.method, None, hdr)
        return dmstr(res) if status == 200 else None

class NeCfg_One():
    ''' doc: 2.1.5 '''
    def __init__(self):
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_port = 8182
        self.url_pathpat = "/restconf/config/huawei-ac-inventory:inventory-cfg/nes/{neid}"
        self.method = "GET"

    def dotan(self, neid):
        hdr = token.todic()
        url_pathpat = self.url_pathpat.format(neid=neid)
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, url_pathpat, self.method, None, hdr)
        return dmstr(res) if status == 200 else None


class NeOper_All():
    ''' doc: 2.1.2 '''
    def __init__(self):
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_port = 8182
        self.url_pathpat = "/restconf/operational/huawei-ac-inventory:inventory-oper/nes"
        self.method = "GET"

    def dotan(self):
        hdr = token.todic()
        status, reason, res = hgetx(self, self.method, None, hdr)
        return dmstr(res) if status == 200 else None

class NeOper_One():
    ''' doc: 2.1.6 '''
    def __init__(self):
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_port = 8182
        self.url_pathpat = "/restconf/operational/huawei-ac-inventory:inventory-oper/nes/{neid}"
        self.method = "GET"

    def dotan(self, neid):
        hdr = token.todic()
        url_pathpat = self.url_pathpat.format(neid=neid)
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, url_pathpat, self.method, None, hdr)
        return dmstr(res) if status == 200 else None



class LspInfos():
    ''' doc: 2.4.6 '''
    def __init__(self):
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_scheme = "http"                    # auv: test code, FIXME
        self.url_hostname = "10.9.63.208"           # auv: test code, FIXME
        self.url_port = 8182
        self.url_pathpat = "/restconf/operational/huawei-ac-lsp-reoptimization:lsp-reoptimization-oper/lsp-infos"
        self.method = "GET"

    def dotan(self):
        hdr = token.todic()
        status, reason, res = hgetx(self, self.method, None, hdr)
        return dmstr(res) if status == 200 else None


class PceReoptimizationByTunnel():
    ''' doc: 2.4.4 '''
    def __init__(self):
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_scheme = "http"                    # auv: test code, FIXME
        self.url_hostname = "10.9.63.208"           # auv: test code, FIXME
        self.url_port = 8182
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
        status, reason, res = hgetx(self, self.method, req, hdr)
        return dmstr(res) if status == 200 else None


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
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_scheme = "http"                    # auv: test code, FIXME
        self.url_hostname = "10.9.63.208"           # auv: test code, FIXME
        self.url_port = 8182
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

        args = dotmap.DotMap(req["args"])

        def getloopback(router_uid):
            e = einfo.fr_uid(router_uid)
            return e.get("ip_str") if e else None

        fr_ip = getloopback(args.get("from_router_uid")) or "222.222.222.222"
        if not fr_ip:
            klog.e("dotan")
            return None
        to_ip = getloopback(args.get("to_router_uid")) or "221.221.221.221"
        if not to_ip:
            klog.e("dotan")
            return None

        hdr = token.todic()

        tunnel_name = args.get("name")
        klog.d(tunnel_name)

        # 1. Fill the parameter will be sent to web service
        dic = dotmap.DotMap()
        dic["tunnel-name"] = tunnel_name
        dic["tunnel-type"] = "te"
        dic["manage-protocol"] = "netconf"
        dic["control-mode"] = "delegate"
        dic["path-setup-type"] = "rsvp-te"

        dic["source"] = {
            "ne-id": "d056ee16-63da-4621-a210-740a72c6b468",    # FIXME
            "ip-address": fr_ip
        }
        dic["destination"] = {
            "ne-id": "bbf4f50c-32cd-4bfb-ade8-e803d4334af0",    # FIXME
            "ip-address": to_ip
        }

        status, reason, res = hgetx(self, self.method, dic, hdr)
        varprt(hdr, "HDR")
        varprt(dic, "DIC")
        klog.d("status:%s" % status)
        if status != 201:
            klog.e("status is not 201, it is %d" % status)
            return None

        newlsp = dmstr(res)

        # 2. ensure approve (doc: 2.4.4) by PceReoptimizationByTunnel
        req = {"auto-approve": True, "reoptimization-by-tunnelname": {"tunnel-name": tunnel_name}}
        res = call(PceReoptimizationByTunnel, req)
        klog.d(varfmt(res, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))


        if not res:
            return None

        # 3. prepare the return value
        ret = dotmap.DotMap()

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
        start = time.time()
        while True:
            if time.time() - start > 30:
                return None

            obj = call(LspInfos)
            for d in obj.get("lsp-info", ()):
                if d.get("tunnel-name") == tunnel_name:

                    # Skip backup lsp
                    role = d["lsp-role"]
                    if role != "master":
                        continue

                    # XXX: wake till it up?
                    oper_state = d.get("oper-state")
                    ret.status = 1 if oper_state == "operate-up" else 0

                    # Fill the hop_list
                    for hop in d.hops.hop:
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

                    return ret

            time.sleep(0.5)

        # 4. Return
        return ret



################################################
class TunnelModify():
    '''ms_controller_update_lsp

    FIXME: Not defined yet

    NOTE: The parameter is same as TunnelCreate
    '''

    def __init__(self):
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_port = 8182
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
        info = call(TunnelQueryInstance, tunnel_name)

        dic = dotmap.DotMap()
        dic["tunnel-name"] = info["tunnel-name"]
        dic["tunnel-type"] = inof["tunnel-type"]
        dic["manage-protocol"] = inof["manage-protocol"]
        dic["control-mode"] = inof["control-mode"]
        dic["path-setup-type"] = inof["path-setup-type"]
        dic["source"] = inof["source"]
        dic["destination"] = inof["destination"]
        dic["tunnel-constraint"]["bandwidth"] = args.bandwidth

        hdr = token.todic()

        status, reason, res = hgetx(self, self.method, dic, hdr)
        if status != 200:
            return None

        return dmstr(res)



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
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_port = 8182
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel/{tunnel_name}/tunnel-constraint"
        self.method = "PUT"

    def dotan(self, tunnel_name, oper_bandwidth):
        hdr = token.todic()

        dic = {"tunnel-name": tunnel_name, "oper-bandwidth": oper_bandwidth}

        url_pathpat = self.url_pathpat.format(tunnel_name=tunnel_name)
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, url_pathpat, self.method, dic, hdr)
        obj = dmstr(res)
        return obj



################################################

class TunnelDelete():
    '''ms_controller_del_lsp

    FIXME: Not defined in doc
    '''
    def __init__(self):
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_port = 8182
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

        klog.d(varfmt(ci, "CI"))
        tunnel_name = ci["name"]

        hdr = token.todic()

        url_pathpat = self.url_pathpat.format(tunnel_name=tunnel_name)
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, url_pathpat, self.method, None, hdr)
        if status != 200:
            return None

        resp = {
            "uid": ci["uid"],
            "from_router_name": ci["from_router_name"],
            "to_router_name": ci["to_router_name"],
            "bandwidth": ci["bandwidth"],
            "to_router_uid": ci["to_router_uid"],
            "from_router_uid": ci["from_router_uid"],
            "name": ci["name"],
            "hop_list": ci["hop_list"],
            "path": userdata["path"],
            "status": userdata["status"],
            "priority": ci["priority"],
            "delay": ci["delay"],
            "user_data": userdata,
        }

        return dotmap.DotMap(resp)





################################################

class TunnelQueryInstance():
    def __init__(self):
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_port = 8182
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/p2p-tunnel/tunnels/tunnel/{tunnel_name}"
        self.method = "GET"

    def dotan(self, tunnel_name):
        hdr = token.todic()

        url_pathpat = self.url_pathpat.format(tunnel_name=tunnel_name)
        status, reason, res = hget(self.url_scheme, self.url_hostname, self.url_port, url_pathpat, self.method, dic, hdr)
        if status != 200:
            return None

        obj = dmstr(res)
        return obj



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
        self.url_scheme = "https"
        self.url_hostname = "172.19.45.185"
        self.url_port = 8182
        self.url_pathpat = "/restconf/config/huawei-ac-ute-tunnel:ute-tunnel-cfg/query-te-tunnels-nbi"
        self.method = "POST"

    def dotan(self, req=None):
        hdr = token.todic()

        dic = dmstr(self.templ)
        dic.update(req)

        status, reason, res = hgetx(self, self.method, dic, hdr)
        obj = dmstr(res)
        return obj

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

        userdata = req["args"]["user_data"]
        ci = req["args"]["user_data"]["create_info"]
        resp = {
            "uid": ci["uid"],
            "from_router_name": ci["from_router_name"],
            "to_router_name": ci["to_router_name"],
            "bandwidth": ci["bandwidth"],
            "to_router_uid": ci["to_router_uid"],
            "from_router_uid": ci["from_router_uid"],
            "name": ci["name"],
            "hop_list": ci["hop_list"],
            "path": userdata["path"],
            "status": userdata["status"],
            "priority": ci["priority"],
            "delay": ci["delay"],
            "user_data": userdata,
        }

        res = {"lsps": [resp]}
        return dotmap.DotMap(res)



'''
### #####################################################################
# mcon etc
#
from roar import CallManager, CmdServer_Socket

callman = CallManager()
cmdserv = CmdServer_Socket(callman, 55000)
cmdserv.start()

@callman.deccmd()
def token(cmdctx, calldic):
    return token.todic()
'''


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
        return dotmap.DotMap()


def odic(indic):
    odic = dotmap.DotMap()

    odic.response = indic.request
    odic.trans_id = indic.trans_id
    odic.ts = time.strftime("%Y%m%d%H%M%S")

    odic.result = dotmap.DotMap()

    odic.err_code = 0
    odic.msg = None

    return odic


@post("/create")
def tunnelCreate():
    calldic = idic()
    resp = call(TunnelCreate, calldic.get_args())
    varprt(resp)

    respdic = odic(calldic)
    return json.dumps(respdic)


@post("/modify")
def tunnelModify():
    calldic = idic()
    resp = call(TunnelModify, calldic.get_args())
    varprt(resp)

    respdic = odic(calldic)
    return json.dumps(respdic)


@post("/constrait")
def tunnelConstrait():
    calldic = idic()
    resp = call(TunnelConstrait, calldic.get_args())
    varprt(resp)

    respdic = odic(calldic)
    return json.dumps(respdic)


@post("/delete")
def tunnelDelete():
    calldic = idic()
    resp = call(TunnelDelete, calldic.get_args())
    varprt(resp)

    respdic = odic(calldic)
    return json.dumps(respdic)


@post("/queryinst")
def tunnelQueryInstance():
    calldic = idic()
    resp = call(TunnelQueryInstance, calldic.get_args())
    varprt(resp)

    respdic = odic(calldic)
    return json.dumps(respdic)



@post("/querylist")
def tunnelQueryList():
    calldic = idic()
    resp = call(TunnelQueryList, calldic.get_args())
    varprt(resp)

    respdic = odic(calldic)
    varprt(respdic)
    return json.dumps(respdic)





if 0:
    obj = call(LspInfos)
    hops = {}
    for d in obj.get("lsp-info"):
        name = d["tunnel-name"]
        role = d["lsp-role"]
        if role != "master":
            continue
        print name
        for h in d["hops"]["hop"]:
            print h["lsr-id"]

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

if __name__ == "__main__":
    run(server='paste', host='0.0.0.0', port=10001, debug=True)


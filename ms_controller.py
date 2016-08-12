#!/usr/bin/python
# -*- coding: utf-8 -*-
from sqlite3 import Time

__author__ = 'Siag'

import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
import tornado.httpclient
import tornado.gen
import tornado.locks
import json
import threading
import traceback
import datetime
import time
import copy
import httplib
import urlparse

microsrv_te_lsp_man_url = 'http://10.9.63.208:7799/lsp/'
microsrv_te_flow_man_url = 'http://10.9.63.208:7799/sche/'
# microsrv_te_lsp_man_url = 'http://10.9.63.88:32772'
# microsrv_te_flow_man_url = 'http://10.9.63.88:32773'
microsrv_status_check_times = 30
microsrv_status_check_duration = 5
microsrv_equip_map = {"PE14Z": {"vendor": "ZTE", "uid": "PE14Z", "pos": "Old village of Gao", "community": "roastedchikenPE14Z", "ip_str": "14.14.14.14", "y": 48.9, "x": 113.8, "model": "aladin", "name": "PE14Z"}, "PE21A": {"vendor": "ALU", "uid": "PE21A", "pos": "Old village of Gao", "community": "roastedchikenPE21A", "ip_str": "21.21.21.21", "y": 48.9, "x": 113.8, "model": "aladin", "name": "PE21A"}, "PE12J": {"vendor": "JUNIPER", "uid": "PE12J", "pos": "Old village of Gao", "community": "roastedchikenPE12J", "ip_str": "12.12.12.12", "y": 48.9, "x": 113.8, "model": "aladin", "name": "PE12J"}, "R1Z": {"vendor": "ZTE", "uid": "R1Z", "pos": "Old village of Gao", "community": "roastedchikenR1Z", "ip_str": "1.1.1.1", "y": 48.9, "x": 113.8, "model": "aladin", "name": "R1Z"}, "PE13C": {"vendor": "CISCO", "uid": "PE13C", "pos": "Old village of Gao", "community": "roastedchikenPE13C", "ip_str": "13.13.13.13", "y": 48.9, "x": 113.8, "model": "aladin", "name": "PE13C"}, "PE22J": {"vendor": "JUNIPER", "uid": "PE22J", "pos": "Old village of Gao", "community": "roastedchikenPE22J", "ip_str": "22.22.22.22", "y": 48.9, "x": 113.8, "model": "aladin", "name": "PE22J"}, "PE24Z": {"vendor": "ZTE", "uid": "PE24Z", "pos": "Old village of Gao", "community": "roastedchikenPE24Z", "ip_str": "24.24.24.24", "y": 48.9, "x": 113.8, "model": "aladin", "name": "PE24Z"}, "PE11A": {"vendor": "ALU", "uid": "PE11A", "pos": "Old village of Gao", "community": "roastedchikenPE11A", "ip_str": "11.11.11.11", "y": 48.9, "x": 113.8, "model": "aladin", "name": "PE11A"}, "R3Z": {"vendor": "ZTE", "uid": "R3Z", "pos": "Old village of Gao", "community": "roastedchikenR3Z", "ip_str": "3.3.3.3", "y": 48.9, "x": 113.8, "model": "aladin", "name": "R3Z"}, "R6Z": {"vendor": "ZTE", "uid": "R6Z", "pos": "Old village of Gao", "community": "roastedchikenR6Z", "ip_str": "6.6.6.6", "y": 48.9, "x": 113.8, "model": "aladin", "name": "R6Z"}, "PE23C": {"vendor": "CISCO", "uid": "PE23C", "pos": "Old village of Gao", "community": "roastedchikenPE23C", "ip_str": "23.23.23.23", "y": 48.9, "x": 113.8, "model": "aladin", "name": "PE23C"}, "R4Z": {"vendor": "ZTE", "uid": "R4Z", "pos": "Old village of Gao", "community": "roastedchikenR4Z", "ip_str": "4.4.4.4", "y": 48.9, "x": 113.8, "model": "aladin", "name": "R4Z"}}
microsrv_equip_loopback_uid_map = {"13.13.13.13": "PE13C", "12.12.12.12": "PE12J", "24.24.24.24": "PE24Z", "22.22.22.22": "PE22J", "21.21.21.21": "PE21A", "4.4.4.4": "R4Z", "6.6.6.6": "R6Z", "11.11.11.11": "PE11A", "1.1.1.1": "R1Z", "23.23.23.23": "PE23C", "14.14.14.14": "PE14Z", "3.3.3.3": "R3Z"}
# Not Scheduled(-1), scheduling(0), scheduled(1), De-scheduling(2)
microsrv_flow_status_map = {"active":1, "no_scheduled":-1}
microsrv_flow_template = {"flow_src": "", "flow_dst": "", "flow_uid": "","status":1, "user_data": {}}
# LSP status:   creating(0), up(1), down(-1), missing(-2), deleting(2), deleted(3)
microsrv_lsp_status_map = {"created":0, "up":1, "down":-1, "missing":-2, "removed":2, "deleted":3}
microsrv_lsp_template = {"uid": "lsp_0", "from_router_name": "", "to_router_name": "", "bandwidth": "", "to_router_uid": "", "from_router_uid": "", "name": "", "hop_list":[], "path":[], "status":0, "user_data":{}}
#juniper
microsrv_juniper_controller_host = "https://219.141.189.67:8443"
microsrv_juniper_controller_url = "/NorthStar/API/v1/tenant/1/topology/1/te-lsps/"
microsrv_juniper_controller_token_url = "/oauth2/token/"
microsrv_juniper_headers = {'Authorization': 'Bearer 5qY8ONtB7QTUte0fizDi8Yfe89MPZaw3FJhjYTSnwOQ=', 'Content-Type': 'application/json', 'Cache-Control': 'no-cache'}

#zte
microsrv_zte_controller_host = "http://219.141.189.70:8181"
microsrv_zte_controller_url = "/restconf/operations/"
microsrv_zte_headers = {'Authorization': 'Basic YWRtaW46YWRtaW4=', 'Content-Type': 'application/yang.data+json', 'Cache-Control': 'no-cache'}
#alu
microsrv_alu_controller_host = "http://219.141.189.68"
microsrv_alu_controller_url = "/sdn/"
microsrv_alu_headers = {'Authorization': 'Basic dGVzdDp0ZXN0'}
microsrv_alu_nodename_maps = {"11.11.11.11":"1","12.12.12.12":"2","13.13.13.13":"3","1.1.1.1":"4","3.3.3.3":"5","4.4.4.4":"6","6.6.6.6":"7","21.21.21.21":"8","22.22.22.22":"9","23.23.23.23":"10","14.14.14.14":"11","24.24.24.24":"12"}
microsrv_alu_nodeid_maps = {"1":"11.11.11.11","2":"12.12.12.12","3":"13.13.13.13","4":"1.1.1.1","5":"3.3.3.3","6":"4.4.4.4","7":"6.6.6.6","8":"21.21.21.21","9":"22.22.22.22","10":"23.23.23.23","11":"14.14.14.14","12":"24.24.24.24"}

class useTronadoResp():
    def __init__(self):
        self.code = 0
        self.body = ''
    pass

class base_controller(object):

    def __init__(self):
        self.sub_req_body = ''
        self.url = ''
        self.method = ''
        self.headers = ''
        self.validate_cert = False
        self.useTornado = True

    def process_response(self, resp, req, e_need_fresh, e_fresh_suc):
        print('base_process_response')
        # result = {}
        pass

    @tornado.gen.coroutine
    def do_pure_query(self, req_url, req_method, req_body):
        result = None
        try:
            print(">>> " + req_body)
            http_req = tornado.httpclient.HTTPRequest(req_url, method = req_method, body = req_body)
            client = tornado.httpclient.AsyncHTTPClient()
            result = yield tornado.gen.Task(client.fetch, http_req)
            if (result.code == 599):
                urlp = urlparse.urlsplit(req_url)
                conn = httplib.HTTPConnection(urlp.hostname, urlp.port, timeout=10)
                conn.request(req_method, urlp.path, req_body, {})
                httpres = conn.getresponse()
                result = useTronadoResp()
                result.code = httpres.status
                result.body = httpres.read()
            print("<<< " + str(result.code) + "/" + str(result.body))
            pass
        except:
            traceback.print_exc()
            pass
        raise tornado.gen.Return(result)
        pass

    @tornado.gen.coroutine
    def do_query(self, req, e_need_fresh, e_fresh_suc):
        result = None
        try:
            if (self.useTornado):
                http_req = tornado.httpclient.HTTPRequest(self.url, method = self.method, body = self.sub_req_body, headers = self.headers, validate_cert = self.validate_cert)
                client = tornado.httpclient.AsyncHTTPClient()
                resp = yield tornado.gen.Task(client.fetch, http_req)
                print(str(resp.code) + "/" + str(resp.body))
                result = yield self.process_response(resp, req, e_need_fresh, e_fresh_suc)
                pass
            else:
                print("#599 solution...")
                urlp = urlparse.urlsplit(self.url)
                conn = httplib.HTTPConnection(urlp.hostname, urlp.port, timeout=10)
                conn.request(self.method, urlp.path, self.sub_req_body, self.headers)
                httpres = conn.getresponse()
                resp = useTronadoResp()
                resp.code = httpres.status
                resp.body = httpres.read()
                print(str(resp.code) + "/" + str(resp.body))
                result = yield self.process_response(resp, req, e_need_fresh, e_fresh_suc)
                pass
        except:
            traceback.print_exc()
            pass

        raise tornado.gen.Return(result)
        pass

    def form_request(self,req):
        print('base_form_request')
        '''
        Form the vendor-specific request txt (usually a json string)
        '''
        pass

    def form_url(self, req):
        print('base_form_url')
        pass

    def form_method(self, req):
        print('base_form_method')
        pass

    pass


class juniper_controller(base_controller):
    def __init__(self):
        super(juniper_controller, self).__init__()
        self.sub_req_body = None
        self.url = microsrv_juniper_controller_host + microsrv_juniper_controller_url
        #need implement authorization function
        self.headers = microsrv_juniper_headers
        self.method = 'GET'
        self.validate_cert = False

        self.add_lsp_template = {"name":"ctbri_te_juniper_017", "from":{"topoObjectType":"ipv4", "address":"2.2.2.2"}, "to":{"topoObjectType":"ipv4","address": "4.4.4.4"},  "plannedProperties":{ "setupPriority":7, "holdingPriority":7, "bandwidth":"717m" } }

        self.request_url_map = {'ms_controller_get_lsp': '',
                           'ms_controller_del_lsp': '',
                           'ms_controller_update_lsp': '',
                           'ms_controller_add_lsp' : '',
                           'ms_controller_del_flow' : '',
                           'ms_controller_add_flow' : ''}

        self.request_method__map = {'ms_controller_get_lsp': 'GET',
                           'ms_controller_del_lsp': 'DELETE',
                           'ms_controller_update_lsp':'POST',
                           'ms_controller_add_lsp' : 'POST',
                           'ms_controller_del_flow' : 'DELETE',
                           'ms_controller_add_flow' : 'POST'}

        self.request_body_map = {'ms_controller_get_lsp': self.form_get_lsp_request,
                           'ms_controller_del_lsp': self.form_del_lsp_request,
                           'ms_controller_update_lsp': self.form_update_lsp_request,
                           'ms_controller_add_lsp' : self.form_add_lsp_request,
                           'ms_controller_del_flow' : self.form_del_flow_request,
                           'ms_controller_add_flow' : self.form_add_flow_request}

        self.response_process_map = {'ms_controller_get_lsp': self.process_get_lsp_response,
                           'ms_controller_del_lsp': self.process_common_response,
                           'ms_controller_update_lsp': self.process_common_response,
                           'ms_controller_add_lsp' : self.process_common_response,
                           'ms_controller_del_flow' : self.process_common_response,
                           'ms_controller_add_flow' : self.process_common_response}

        self.resp_key_map = {"uid": "['lspIndex']",
                             "from_router_name": "", #"from": { "topoObjectType": "ipv4", "address": "2.2.2.2" },
                             "to_router_name": "",
                             "bandwidth": "['plannedProperties']['bandwidth']",
                             "to_router_uid": "['to']['address']",
                             "from_router_uid": "['from']['address']",
                             "name": "['name']"}

    @tornado.gen.coroutine
    def token_refresh(self):
        '''
        POST /oauth2/token HTTP/1.1
        Host: 219.141.189.67:8443
        Authorization: Basic YWRtaW46YWRtaW4xMjM=
        Cache-Control: no-cache
        Postman-Token: af7446d8-9e23-16d0-c1ea-3d4284bb66ea
        Content-Type: application/x-www-form-urlencoded

        grant_type=password&username=admin&password=admin123
        '''
        result = False
        token_headers = {'Authorization': 'Basic YWRtaW46YWRtaW4xMjM=', 'Content-Type': 'application/x-www-form-urlencoded', 'Cache-Control': 'no-cache'}
        token_body = 'grant_type=password&username=admin&password=admin123'
        try:
            http_req = tornado.httpclient.HTTPRequest(microsrv_juniper_controller_host + microsrv_juniper_controller_token_url, method = 'POST', body = token_body, headers = token_headers, validate_cert = False)
            client = tornado.httpclient.AsyncHTTPClient()
            resp = yield tornado.gen.Task(client.fetch, http_req)
            print(str(resp.code) + "/" + str(resp.body))
            #200/{"access_token":"7w0H2r1zi5P/BSz4nkxcPUZtGWuBMdGHZaWiQQTUQ0c=","token_type":"Bearer"}
            if (resp.code == 200):
                result = True
                resp_body = json.loads(resp.body)
                self.headers['Authorization'] = resp_body['token_type'] + ' ' + resp_body['access_token']
                pass
            # result = self.process_response(resp, req)
        except:
            traceback.print_exc()
            pass

        raise tornado.gen.Return(result)
        pass

    def form_url(self, req):
        self.url += self.request_url_map[req['request']]
        pass

    def form_method(self, req):
        self.method = self.request_method__map[req['request']]
        pass

    def form_request(self,req):
        self.sub_req_body = self.request_body_map[req['request']](req)
        pass

    def form_get_lsp_request(self, req):
        # case 1: get an lsp by uid(lspIndex)
        # GET /NorthStar/API/v1/tenant/1/topology/1/te-lsps/21
        if ('uid' in req['args']):
            self.url += req['args']['uid']
            pass
        # case 2: geta an lsp by name(lspName)
        # GET /NorthStar/API/v1/tenant/1/topology/1/te-lsps/search?name=999
        elif ('name' in req['args']):
            self.url += 'search?name=' + req['args']['name']
            pass
        # case 3: get all lsps
        else:
            pass
        print('juniper controller:' + self.url)
        pass

    def form_del_lsp_request(self, req):
        if ('uid' in req['args']):
            self.url += req['args']['uid']
            pass
        pass

    def form_update_lsp_request(self, req):

        pass

    def form_add_lsp_request(self, req):
        add_lsp_dict = self.add_lsp_template
        # modify add_lsp_dict here
        sub_req = req['args']
        for lsp_key in self.resp_key_map.keys():
            if(lsp_key in req['args'] and self.resp_key_map[lsp_key]):
                if(lsp_key == 'uid'):
                    continue
                elif(lsp_key == 'from_router_uid'):
                    add_lsp_dict['from']['address'] = microsrv_equip_map[sub_req[lsp_key]]['ip_str']
                    pass
                elif(lsp_key == 'to_router_uid'):
                    add_lsp_dict['to']['address'] = microsrv_equip_map[sub_req[lsp_key]]['ip_str']
                    pass
                # add_lsp_dict[self.resp_key_map[lsp_key]] = req[lsp_key]
                # add_lsp_dict[from][address] = sub_req[lsp_key]
                exec("%s%s = sub_req[lsp_key]" % ("add_lsp_dict", self.resp_key_map[lsp_key]))
                pass
        print('juniper controller:' + json.dumps(add_lsp_dict))
        return json.dumps(add_lsp_dict)
        pass

    def form_del_flow_request(self, req):

        pass

    def form_add_flow_request(self, req):

        pass

    @tornado.gen.coroutine
    def process_response(self, resp, req, e_need_fresh, e_fresh_suc):
        print('juniper_process_response')
        result = {} #resp.body
        #if fail need resolve here
        if (resp.code < 300):
            result = self.response_process_map[req['request']](resp, req)
            raise tornado.gen.Return(result)
            pass
        elif (resp.code == 401):
            #token invalidate
            if (e_need_fresh.is_set() == False):
                print('set fresh clear fresh_suc')
                e_fresh_suc.clear()
                e_need_fresh.set()
                pass
            yield e_fresh_suc.wait()
            result = yield self.do_query(req, e_need_fresh, e_fresh_suc)
            raise tornado.gen.Return(result)
            # if (yield self.token_refresh()):
            #     print('token refresh ok')
            #     result = yield self.do_query(req)
            #     raise tornado.gen.Return(result)
            #     pass
            # else:
            #     raise tornado.gen.Return(resp.body)
            pass
        else:
            result['err_code'] = resp.code
            result['msg'] = resp.body
            raise tornado.gen.Return(result)
            pass
        pass

    def process_get_lsp_response(self, resp, req):
        #convert to microsvr format
        result = {'lsps':[]}
        if ('uid' in req['args'] or 'name' in req['args']):
            lsp_item = json.loads(resp.body)
            self.lsp_detail = copy.deepcopy(microsrv_lsp_template) #dict copy, different from dict.deepcopy
            for lsp_key in self.resp_key_map.keys():
                if (self.resp_key_map[lsp_key]):
                    try:
                        # lsp_detail[lsp_key] = eval("%s%s" % (lsp_key, self.resp_key_map[lsp_key]))
                        # x = eval("%s%s" % ("lsp_item", self.resp_key_map[lsp_key]))
                        self.lsp_detail[lsp_key] = eval("%s%s" % ("lsp_item", self.resp_key_map[lsp_key]))
                        pass
                    except:
                        traceback.print_exc()
                    pass
            result['lsps'].append(self.lsp_detail)
            return result
            pass
        else:
            # result['lsps'].append({})
            for lsp_item in json.loads(resp.body):
                try:
                    self.lsp_detail = copy.deepcopy(microsrv_lsp_template) #dict copy, different from dict.deepcopy
                    for lsp_key in self.resp_key_map.keys():
                        if (self.resp_key_map[lsp_key]):
                            try:
                                # lsp_detail[lsp_key] = eval("%s%s" % (lsp_key, self.resp_key_map[lsp_key]))
                                # x = eval("%s%s" % ("lsp_item", self.resp_key_map[lsp_key]))
                                self.lsp_detail[lsp_key] = eval("%s%s" % ("lsp_item", self.resp_key_map[lsp_key]))
                                pass
                            except:
                                traceback.print_exc()
                            pass
                    result['lsps'].append(self.lsp_detail)
                    del self.lsp_detail
                    pass
                except:
                    traceback.print_exc()
                pass
            return result
            pass
        pass

    def process_common_response(self, resp, req):
        return {} #resp.body
        pass

    pass


class cisco_controller(base_controller):
    def __init__(self):
        super(cisco_controller, self).__init__()
        pass
    pass

class zte_controller(base_controller):
    def __init__(self):
        super(zte_controller, self).__init__()
        self.sub_req_body = None
        self.url = microsrv_zte_controller_host + microsrv_zte_controller_url
        self.headers = microsrv_zte_headers
        self.method = 'POST'
        self.validate_cert = False
        self.useTornado = True

        self.request_url_map = {'ms_controller_get_lsp': 'tunnel:query-all-tunnels',
                                'ms_controller_get_an_lsp': 'tunnel:query-tunnel-by-uuid',
                           'ms_controller_del_lsp': 'tunnel:delete-tunnel',
                           'ms_controller_update_lsp': '',
                           'ms_controller_add_lsp' : 'tunnel:create-tunnel',
                           'ms_controller_del_flow' : 'traffic-policy:binding-interface',
                           'ms_controller_add_flow' : 'traffic-policy:create-traffic-policy-template',
                           'ms_controller_add_flow_2' : 'traffic-policy:binding-interface',
                           'ms_controller_del_flow_2' : 'traffic-policy:delete-traffic-policy-template',
                           'ms_controller_get_flow' : 'traffic-policy:query-traffic-policy-template'}

        self.request_body_map = {'ms_controller_get_lsp': self.form_get_lsp_request,
                           'ms_controller_del_lsp': self.form_del_lsp_request,
                           'ms_controller_update_lsp': self.form_update_lsp_request,
                           'ms_controller_add_lsp' : self.form_add_lsp_request,
                           'ms_controller_del_flow' : self.form_del_flow_request,
                           'ms_controller_del_flow_2' : self.form_del_flow_request_2,
                           'ms_controller_get_flow' : self.form_get_flow_request,
                           'ms_controller_add_flow' : self.form_add_flow_request,
                           'ms_controller_add_flow_2' : self.form_add_flow_request_2}

        self.response_process_map = {'ms_controller_get_lsp': self.process_get_lsp_response,
                           'ms_controller_del_lsp': self.process_del_lsp_response,
                           'ms_controller_update_lsp': self.process_common_response,
                           'ms_controller_add_lsp' : self.process_add_lsp_response,
                           'ms_controller_del_flow' : self.process_del_flow_response,
                           'ms_controller_del_flow_2' : self.process_del_flow_response_2,
                           'ms_controller_get_flow' : self.process_get_flow_response,
                           'ms_controller_add_flow' : self.process_add_flow_response,
                           'ms_controller_add_flow_2' : self.process_add_flow_response_2}

        self.resp_key_map = {"uid": "['tunnel-id']",
                             "from_router_name": "", #"from": { "topoObjectType": "ipv4", "address": "2.2.2.2" },
                             "to_router_name": "",
                             "bandwidth": "['te-argument']['bandwidth']",
                             "to_router_uid": "['egress-node-id']",
                             "from_router_uid": "['ingress-node-id']",
                             "hop_list":"['te-argument']['next-address']",
                             "path":"['path']",
                             "status":"['status']",
                             "user_data":"",
                             "name": "['tunnel-uuid']"}

    def form_url(self, req):
        self.url += self.request_url_map[req['request']]
        pass

    def form_method(self, req):
        pass

    def form_request(self,req):
        self.sub_req_body = self.request_body_map[req['request']](req)
        pass

    def form_get_lsp_request(self, req):
        # case 1: get an lsp by name(lspName)
        # GET /NorthStar/API/v1/tenant/1/topology/1/te-lsps/search?name=999
        sub_body = {"input":{}}
        if ('name' in req['args']):
            #POST /restconf/operations/tunnel:query-tunnel-by-uuid
            #{"input":{"tunnel-uuid":"lsp_zte_24_6_4_14"}}
            self.url = microsrv_zte_controller_host + microsrv_zte_controller_url + self.request_url_map['ms_controller_get_an_lsp']
            sub_body['input'] = {'tunnel-uuid':req['args']['name']}
            print('zte controller get an lsp body:' + str(sub_body))
            pass
        elif('user_data' in req['args']):
            #POST /restconf/operations/tunnel:query-tunnel-by-uuid
            #{"input":{"tunnel-uuid":"lsp_zte_24_6_4_14"}}
            self.url = microsrv_zte_controller_host + microsrv_zte_controller_url + self.request_url_map['ms_controller_get_an_lsp']
            sub_body['input'] = {'tunnel-uuid':req['args']['user_data']['lsp_name']}
            print('zte controller get an lsp body:' + str(sub_body))
            pass
        # case 2: get all lsps
        else:
            pass
        print('zte controller:' + self.url)
        return json.dumps(sub_body)
        pass

    def form_del_lsp_request(self, req):
        sub_body = {"input":{}}
        if ('name' in req['args']):
            #{"input":{"tunnel-uuid":"lsp_zte_24_6_4_14"}}
            sub_body['input'] = {'tunnel-uuid':req['args']['name']}
            print('zte controller del an lsp body:' + str(sub_body))
            pass
        elif('user_data' in req['args']):
            #{"input":{"tunnel-uuid":"lsp_zte_24_6_4_14"}}
            sub_body['input'] = {'tunnel-uuid':req['args']['user_data']['lsp_name']}
            print('zte controller del an lsp body:' + str(sub_body))
            pass
        print('zte controller:' + self.url)
        return json.dumps(sub_body)
        pass

    def form_update_lsp_request(self, req):

        pass

    def form_add_lsp_request(self, req):
        #{"input" : {"tunnel-info-in":[{"tunnel-uuid":"lsp_zte_14_24","ingress-node-id":"14.14.14.14","egress-node-id":"24.24.24.24","bandwidth":234,"next-address":[]}]}}
        add_lsp_super_template = {"input" : {"tunnel-info-in":[]}}
        add_lsp_template = {"tunnel-uuid":"","ingress-node-id":"","egress-node-id":"","bandwidth":234,"next-address":[]}
        # modify add_lsp_dict here
        sub_req = req['args']
        for lsp_key in self.resp_key_map.keys():
            if(lsp_key in req['args'] and self.resp_key_map[lsp_key]):
                if(lsp_key == 'uid'):
                    continue
                    pass
                elif(lsp_key == 'bandwidth'):
                    add_lsp_template['bandwidth'] = int(sub_req[lsp_key]) * 1000000
                    pass
                elif(lsp_key == 'hop_list'):
                    for list_node in sub_req[lsp_key]:
                        if(list_node == sub_req['from_router_uid'] or list_node == sub_req['to_router_uid']):
                            continue
                        next_address_item_temp = {"strict": "false","destination":{"dest-node":""}}
                        next_address_item_temp['destination']['dest-node'] = microsrv_equip_map[list_node]['ip_str']
                        add_lsp_template['next-address'].append(next_address_item_temp)
                        pass
                # add_lsp_dict[self.resp_key_map[lsp_key]] = req[lsp_key]
                # add_lsp_dict[from][address] = sub_req[lsp_key]
                elif(lsp_key == 'from_router_uid'):
                    add_lsp_template['ingress-node-id'] = microsrv_equip_map[sub_req[lsp_key]]['ip_str']
                    pass
                elif(lsp_key == 'to_router_uid'):
                    add_lsp_template['egress-node-id'] = microsrv_equip_map[sub_req[lsp_key]]['ip_str']
                    pass
                else:
                    exec("%s%s = sub_req[lsp_key]" % ("add_lsp_template", self.resp_key_map[lsp_key]))
                    pass
        add_lsp_super_template['input']['tunnel-info-in'].append(add_lsp_template)
        print('zte controller:' + json.dumps(add_lsp_super_template))
        return json.dumps(add_lsp_super_template)
        pass

    def form_del_flow_request(self, req):
        #{"input": {"deleting-traffic-policy": [{"traffic-policy-template-name": "flow_zte_lsp_4_6"}],"node": "14.14.14.14","traffic-direction": "input"}}
        del_flow_request = {"input": {"deleting-traffic-policy": [],"node": "","traffic-direction": "input"}}
        if('user_data' in req['args']):
            if ('from_router_uid' in req['args']['user_data']):
                del_flow_request['input']['node'] = microsrv_equip_map[req['args']['user_data']['from_router_uid']]['ip_str']
                pass
            if ('lsp_name' in req['args']['user_data']):
                del_flow_request['input']['deleting-traffic-policy'].append({"traffic-policy-template-name": 'flow_' + req['args']['user_data']['lsp_name']})
        print('zte controller:' + self.url + '/' + json.dumps(del_flow_request))
        return json.dumps(del_flow_request)
        pass

    def form_del_flow_request_2(self, req):
        #deleting_policy,one more request
        #{"input": {"traffic-policy-template-name": "flow_zte_lsp_4_6"}}
        del_flow_request2 = {"input": {"traffic-policy-template-name": ""}}
        self.url = microsrv_zte_controller_host + microsrv_zte_controller_url + self.request_url_map[req['request']]
        if('lsp_name' in req['args']['user_data']):
            del_flow_request2['input']['traffic-policy-template-name'] = 'flow_' + req['args']['user_data']['lsp_name']
            pass
        print('zte controller:' + self.url + '/' + json.dumps(del_flow_request2))
        return json.dumps(del_flow_request2)
        pass

    def form_add_flow_request(self, req):
        #srcjson:{"args": {"lsp_uid": "xyz123", "flow": {"src": "123.10.88.0/24", "dst": "10.10.20.0/24", "uid": "ips_0"},
        # "user_data": {'lsp_id': '41', 'from_router_uid': 'PE11A', 'lsp_name': 'ALU_S'}}},
        # "request": "ms_controller_add_flow", "ts": "20160718153347", "trans_id": 1468827227}
        #desjson:
        # {"input" :{"traffic-policy-template-name":"","match-elements":{"src-ipv4-address":"","dest-ipv4-address":"" },
        # "match-relation":"match-all", "interfaces": {"interface": [{"ifname": "te_tunnel1" }]}}}
        zte_flow_policy_template = {"input" :{"traffic-policy-template-name":"","match-elements":{}, "match-relation":"match-all", "interfaces": {"interface": []}}}
        if ('flow' in req['args']):
            if('src' in req['args']['flow']):
                zte_flow_policy_template['input']['match-elements']['src-ipv4-address'] = req['args']['flow']['src']
            if('dst' in req['args']['flow']):
                zte_flow_policy_template['input']['match-elements']['dest-ipv4-address'] = req['args']['flow']['dst']
        if ('user_data' in req['args']):
            if('lsp_name' in req['args']['user_data']):
                zte_flow_policy_template['input']['traffic-policy-template-name'] = 'flow_' + req['args']['user_data']['lsp_name']
            if('lsp_id' in req['args']['user_data']):
                zte_flow_policy_template['input']['interfaces']['interface'].append({"ifname":'te_tunnel' + str(req['args']['user_data']['lsp_id'])})
        print('zte controller:' + json.dumps(zte_flow_policy_template))
        return json.dumps(zte_flow_policy_template)
        pass

    def form_add_flow_request_2(self, req):
        #srcjson:{"args": {"lsp_uid": "xyz123", "flow": {"src": "123.10.88.0/24", "dst": "10.10.20.0/24", "uid": "ips_0"},
        # "user_data": {'lsp_id': '41', 'from_router_uid': 'PE11A', 'lsp_name': 'ALU_S'}}},
        # "request": "ms_controller_add_flow", "ts": "20160718153347", "trans_id": 1468827227}
        #binding_interface,one more request for add_flow
        #desjson{"input": {"adding-traffic-policy": [{"traffic-policy-template-name": "flow_zte_lsp_4_6"}],"node": "14.14.14.14","traffic-direction": "input"}}
        add_flow_request2 = {"input": {"adding-traffic-policy": [],"node": "","traffic-direction": "input"}}
        self.url = microsrv_zte_controller_host + microsrv_zte_controller_url + self.request_url_map[req['request']]
        if ('user_data' in req['args']):
            if('lsp_name' in req['args']['user_data']):
                add_flow_request2['input']['adding-traffic-policy'].append({"traffic-policy-template-name": 'flow_' + req['args']['user_data']['lsp_name']})
            if('from_router_uid' in req['args']['user_data']):
                add_flow_request2['input']['node'] = microsrv_equip_map[req['args']['user_data']['from_router_uid']]['ip_str']
        print('zte controller:' + self.url + '/' + json.dumps(add_flow_request2))
        return json.dumps(add_flow_request2)
        pass

    def form_get_flow_request(self, req):
        #599 why?
        self.useTornado = False
        print('zte controller:' + self.url)
        pass

    @tornado.gen.coroutine
    def process_response(self, resp, req, e_need_fresh, e_fresh_suc):
        print('zte_process_response')
        result = {} #resp.body
        #if fail need resolve here
        if (resp.code < 300):
            result = yield self.response_process_map[req['request']](resp, req)
            raise tornado.gen.Return(result)
            pass
        else:
            result['err_code'] = resp.code
            result['msg'] = resp.body
            raise tornado.gen.Return(result)
            pass
        pass

    @tornado.gen.coroutine
    def process_add_lsp_response(self, resp, req):
        '''
        {
          "output": {
            "result": true,
            "info": "success",
            "tunnel-id-info": [
              {
                "tunnel-uuid": "lsp_zte_24_14",
                "tunnel-id": 1
              }
            ]
          }
        }
        200/{"output":{"result":false,"info":"fail"}}
        for lsp create, controller returned is temp status, need get really created status(up)by get_lsp_by_uuid
        1. add time_out(time = 3s) task,params:get_lsp method entry, refresh times, req, resp
        2. if refresh times>15,return get_lsp result to callback
        3. if get_lsp result status change to up, return get_lsp result to callback
        4. lsp create return usr_data(id, name) in order to future delete
        for alu: created--->up
        {"args": {"uid": "14.14.14.14", "from_router_name":"",  "to_router_name": "", "bandwidth": "248", "to_router_uid": "24.24.24.24",
        "from_router_uid": "14.14.14.14",  "hoplist":[], "name": "zte_lsp_14_24_byo"},
        "request": "ms_controller_add_lsp", "ts": "20160601164338", "trans_id": 1464770618}
        '''
        resp_body = json.loads(resp.body)
        check_req = dict.copy(req)
        check_req['request'] = "ms_controller_get_lsp"
        if ('output' in resp_body and 'result' in resp_body['output'] and resp_body['output']['result'] == True):
            tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_add_lsp_status_check, 0, check_req, resp)
        else:
            result = {}
            try:
                result['err_code'] = 1
                result['msg'] = 'add lsp fail'
            except:
                traceback.print_exc()
                pass
            return result
        pass

    @tornado.gen.coroutine
    def process_del_lsp_response(self, resp, req):
        '''
                {
          "output": {
            "result": true,
            "info": "success"
          }
        }
        '''
        resp_body = json.loads(resp.body)
        check_req = dict.copy(req)
        check_req['request'] = "ms_controller_get_lsp"
        if ('output' in resp_body and 'result' in resp_body['output'] and resp_body['output']['result'] == True):
            tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_del_lsp_status_check, 0, check_req, resp)
        else:
            result = {}
            try:
                result['err_code'] = 1
                result['msg'] = 'del lsp fail'
            except:
                traceback.print_exc()
                pass
            return result
        pass

    @tornado.gen.coroutine
    def process_get_lsp_response(self, resp, req):
        #convert to microsvr format
        result = {'lsps':[]}
        if ('name' in req['args']):
            lsp_item = json.loads(resp.body)['output']
            self.lsp_detail = copy.deepcopy(microsrv_lsp_template) #dict copy, different from dict.deepcopy
            for lsp_key in self.resp_key_map.keys():
                if (self.resp_key_map[lsp_key]):
                    try:
                        if(lsp_key == 'hop_list'):
                            if('next-address' in lsp_item['te-argument']):
                            # {"te-argument": { "next-address": [ { "destination": {  "dest-node": "4.4.4.4" },  "strict": false }]}}
                                for hoplistitem in lsp_item['te-argument']['next-address']:
                                    self.lsp_detail[lsp_key].append(microsrv_equip_loopback_uid_map[hoplistitem['destination']['dest-node']])
                                    pass
                            pass
                        elif(lsp_key == 'path'):
                            if('path' in lsp_item):
                                #add first node
                                self.lsp_detail[lsp_key].append(microsrv_equip_loopback_uid_map[lsp_item['ingress-node-id']])
                                #{"path": {"path-link": [{ "link-id": " ",
                                # "source": { "source-node": "14.14.14.14", "source-tp": "10.0.140.14" },
                                # "destination": { "dest-node": "11.11.11.11", "dest-tp": "10.0.140.11" }}]}}
                                for pathitem in lsp_item['path']['path-link']:
                                    self.lsp_detail[lsp_key].append(microsrv_equip_loopback_uid_map[pathitem['destination']['dest-node']])
                                    pass
                            pass
                        elif(lsp_key == 'from_router_uid'):
                            self.lsp_detail[lsp_key] = microsrv_equip_loopback_uid_map[lsp_item['ingress-node-id']]
                            pass
                        elif(lsp_key == 'to_router_uid'):
                            self.lsp_detail[lsp_key] = microsrv_equip_loopback_uid_map[lsp_item['egress-node-id']]
                            pass
                        elif(lsp_key == 'status'):
                            self.lsp_detail[lsp_key] = microsrv_lsp_status_map[lsp_item['status'].lower()]
                            pass
                        else:
                        # lsp_detail[lsp_key] = eval("%s%s" % (lsp_key, self.resp_key_map[lsp_key]))
                        # x = eval("%s%s" % ("lsp_item", self.resp_key_map[lsp_key]))
                            self.lsp_detail[lsp_key] = eval("%s%s" % ("lsp_item", self.resp_key_map[lsp_key]))
                            pass
                    except:
                        traceback.print_exc()
                    pass
            user_data_content = {"lsp_id":"", "lsp_name":"", "from_router_uid":""}
            user_data_content['lsp_id'] = self.lsp_detail['uid']
            user_data_content['lsp_name'] = self.lsp_detail['name']
            user_data_content['from_router_uid'] = self.lsp_detail['from_router_uid']
            self.lsp_detail['user_data'] = user_data_content
            result['lsps'].append(self.lsp_detail)
            del self.lsp_detail
            return result
            pass
        else:
            # result['lsps'].append({})
            if ('query-tunnel-infos' not in json.loads(resp.body)['output']):
                return None
            for lsp_item in json.loads(resp.body)['output']['query-tunnel-infos']:
                try:
                    self.lsp_detail = copy.deepcopy(microsrv_lsp_template) #dict copy, different from dict.deepcopy
                    for lsp_key in self.resp_key_map.keys():
                        if (self.resp_key_map[lsp_key]):
                            try:
                                if(lsp_key == 'hop_list'):
                                    if('next-address' in lsp_item['te-argument']):
                                    # {"te-argument": { "next-address": [ { "destination": {  "dest-node": "4.4.4.4" },  "strict": false }]}}
                                        for hoplistitem in lsp_item['te-argument']['next-address']:
                                            self.lsp_detail[lsp_key].append(microsrv_equip_loopback_uid_map[hoplistitem['destination']['dest-node']])
                                            pass
                                    pass
                                elif(lsp_key == 'path'):
                                    if('path' in lsp_item):
                                        #add first node
                                        self.lsp_detail[lsp_key].append(lsp_item['ingress-node-id'])
                                        #{"path": {"path-link": [{ "link-id": " ",
                                        # "source": { "source-node": "14.14.14.14", "source-tp": "10.0.140.14" },
                                        # "destination": { "dest-node": "11.11.11.11", "dest-tp": "10.0.140.11" }}]}}
                                        for pathitem in lsp_item['path']['path-link']:
                                            self.lsp_detail[lsp_key].append(microsrv_equip_loopback_uid_map[pathitem['destination']['dest-node']])
                                            pass
                                    pass
                                elif(lsp_key == 'from_router_uid'):
                                    self.lsp_detail[lsp_key] = microsrv_equip_loopback_uid_map[lsp_item['ingress-node-id']]
                                    pass
                                elif(lsp_key == 'to_router_uid'):
                                    self.lsp_detail[lsp_key] = microsrv_equip_loopback_uid_map[lsp_item['egress-node-id']]
                                    pass
                                elif(lsp_key == 'status'):
                                    self.lsp_detail[lsp_key] = microsrv_lsp_status_map[lsp_item['status'].lower()]
                                    pass
                                else:
                                    # lsp_detail[lsp_key] = eval("%s%s" % (lsp_key, self.resp_key_map[lsp_key]))
                                    # x = eval("%s%s" % ("lsp_item", self.resp_key_map[lsp_key]))
                                    self.lsp_detail[lsp_key] = eval("%s%s" % ("lsp_item", self.resp_key_map[lsp_key]))
                                    pass
                            except:
                                traceback.print_exc()
                            pass
                    user_data_content = {"lsp_id":"", "lsp_name":"", "from_router_uid":""}
                    user_data_content['lsp_id'] = self.lsp_detail['uid']
                    user_data_content['lsp_name'] = self.lsp_detail['name']
                    user_data_content['from_router_uid'] = self.lsp_detail['from_router_uid']
                    self.lsp_detail['user_data'] = user_data_content
                    result['lsps'].append(self.lsp_detail)
                    del self.lsp_detail
                    pass
                except:
                    traceback.print_exc()
                pass
            return result
            pass
        pass

    @tornado.gen.coroutine
    def process_add_flow_response(self, resp, req):
        #200/{"output":{"result":true,"info":"createTrafficPolicyTemplate success!"}}
        #binding_interface,one more request for add_flow
        #chanage add_flow_requet to add_flow_request_2, in process_add_flow_response_2, need chanage add_flow_requet_2 to add_flow_request for correct resp
        resp_body = json.loads(resp.body)
        result = None
        if ('output' in resp_body and 'result' in resp_body['output'] and resp_body['output']['result'] == True):
            req['request'] = req['request'] + '_2'
            self.form_request(req)
            result = yield self.do_query(req, None, None)
        else:
            result = {}
            try:
                result['err_code'] = 1
                result['msg'] = 'add flow fail'
            except:
                traceback.print_exc()
                pass
        raise tornado.gen.Return(result)
        pass

    @tornado.gen.coroutine
    def process_add_flow_response_2(self, resp, req):
        #200/{"output":{"result":true}}
        #chanage add_flow_requet to add_flow_request_2, in process_add_flow_response_2, need chanage add_flow_requet_2 to add_flow_request for correct resp
        req['request'] = req['request'][0:-2]
        check_req = dict.copy(req)
        check_req['request'] = "ms_controller_get_flow"
        resp_body = json.loads(resp.body)
        # microsrv_flow_template = {"flow_src": "", "flow_dst": "", "flow_uid": "","status":1, "user_data": {}}
        if ('output' in resp_body and 'result' in resp_body['output'] and resp_body['output']['result'] == True):
            check_req['user_data']['flow_id'] = 'flow_' + req['args']['user_data']['lsp_name']
            check_req['user_data']['flow_name'] = 'flow_' + req['args']['user_data']['lsp_name']
            tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_add_flow_status_check, 0, check_req, resp)
        else:
            result = {}
            try:
                result['err_code'] = 1
                result['msg'] = 'add flow fail'
            except:
                traceback.print_exc()
                pass
            return result
        pass

    @tornado.gen.coroutine
    def process_del_flow_response(self, resp, req):
        '''
        {
          "output": {
            "result": true
          }
        }
        '''
        #chanage del_flow_requet to del_flow_request_2, in process_del_flow_response_2, need chanage del_flow_request_2 to del_flow_requet for correct resp
        resp_body = json.loads(resp.body)
        result = None
        if ('output' in resp_body and 'result' in resp_body['output'] and resp_body['output']['result'] == True):
            req['request'] = req['request'] + '_2'
            self.form_request(req)
            result = yield self.do_query(req, None, None)
        else:
            result = {}
            try:
                result['err_code'] = 1
                result['msg'] = 'del flow fail'
            except:
                traceback.print_exc()
                pass
        raise tornado.gen.Return(result)
        pass

    @tornado.gen.coroutine
    def process_del_flow_response_2(self, resp, req):
        '''
            {
              "output": {
                "result": true,
                "info": "deleteTrafficPolicyTemplate success!"
              }
            }
        '''
        req['request'] = req['request'][0:-2]
        check_req = dict.copy(req)
        check_req['request'] = "ms_controller_get_flow"
        resp_body = json.loads(resp.body)
        # microsrv_flow_template = {"flow_src": "", "flow_dst": "", "flow_uid": "","status":1, "user_data": {}}
        if ('output' in resp_body and 'result' in resp_body['output'] and resp_body['output']['result'] == True):
            tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_del_flow_status_check, 0, check_req, resp)
        else:
            result = {}
            try:
                result['err_code'] = 1
                result['msg'] = 'del flow fail'
            except:
                traceback.print_exc()
                pass
        pass

    @tornado.gen.coroutine
    def process_get_flow_response(self, resp, req):
        return resp.body
        pass

    @tornado.gen.coroutine
    def process_common_response(self, resp, req):
        return {} #resp.body
        pass
    pass

class alu_controller(base_controller):
    def __init__(self):
        super(alu_controller, self).__init__()
        self.sub_req_body = None
        self.url = microsrv_alu_controller_host + microsrv_alu_controller_url
        self.headers = microsrv_alu_headers
        self.method = 'GET'
        self.validate_cert = False

        self.add_lsp_template = {"lspname":"alu_lsp","a":"1","z":"8","hoplist":["1","8"],"bandwidth":"111","subnetwork":"snc1"}

        self.request_url_map = {'ms_controller_get_lsp': 'lsp',
                                'ms_controller_get_an_lsp': 'lsp/name:',
                           'ms_controller_get_node': 'topo/subnetwork:snc1/nodes',
                           'ms_controller_del_lsp': 'lsp/subnetwork:snc1/name:',
                           'ms_controller_update_lsp': '',
                           'ms_controller_add_lsp' : 'lsp',
                           'ms_controller_del_flow' : 'rule/ne:',
                           'ms_controller_get_flow' : 'rule/ne:',
                           'ms_controller_add_flow' : 'rule'}

        self.request_method__map = {'ms_controller_get_lsp': 'GET',
                           'ms_controller_get_node': 'GET',
                           'ms_controller_del_lsp': 'DELETE',
                           'ms_controller_update_lsp':'POST',
                           'ms_controller_add_lsp' : 'POST',
                           'ms_controller_del_flow' : 'DELETE',
                           'ms_controller_get_flow' : 'GET',
                           'ms_controller_add_flow' : 'POST'}

        self.request_body_map = {'ms_controller_get_lsp': self.form_get_lsp_request,
                           'ms_controller_get_node': self.form_get_node_request,
                           'ms_controller_del_lsp': self.form_del_lsp_request,
                           'ms_controller_update_lsp': self.form_update_lsp_request,
                           'ms_controller_add_lsp' : self.form_add_lsp_request,
                           'ms_controller_del_flow' : self.form_del_flow_request,
                           'ms_controller_get_flow' : self.form_get_flow_request,
                           'ms_controller_add_flow' : self.form_add_flow_request}

        self.response_process_map = {'ms_controller_get_lsp': self.process_get_lsp_response,
                           'ms_controller_get_node': self.process_get_node_response,
                           'ms_controller_del_lsp': self.process_del_lsp_response,
                           'ms_controller_update_lsp': self.process_common_response,
                           'ms_controller_add_lsp' : self.process_add_lsp_response,
                           'ms_controller_del_flow' : self.process_del_flow_response,
                           'ms_controller_get_flow' : self.process_get_flow_response,
                           'ms_controller_add_flow' : self.process_add_flow_response}

        self.resp_key_map = {"uid": "['id']",
                             "from_router_name":"",
                             "to_router_name": "",
                             "bandwidth": "['bandwidth']",
                             "to_router_uid": "['z']",
                             "from_router_uid": "['a']",
                             "hop_list":"['hopseq']",
                             "path":"",
                             "user_data":"",
                             "status":"['status']",
                             "name": "['name']"}

    def form_url(self, req):
        self.url += self.request_url_map[req['request']]
        pass

    def form_method(self, req):
        self.method = self.request_method__map[req['request']]
        pass

    def form_request(self,req):
        self.sub_req_body = self.request_body_map[req['request']](req)
        pass

    def form_get_lsp_request(self, req):
        # case 1: get an lsp by name(lspName)
        # GET /NorthStar/API/v1/tenant/1/topology/1/te-lsps/search?name=999
        sub_body = {"input":{}}
        if ('name' in req['args']):
            #POST /restconf/operations/tunnel:query-tunnel-by-uuid
            #{"input":{"tunnel-uuid":"lsp_zte_24_6_4_14"}}
            self.url = microsrv_alu_controller_host + microsrv_alu_controller_url + self.request_url_map['ms_controller_get_an_lsp'] + req['args']['name']
            pass
        elif('user_data' in req['args']):
            self.url = microsrv_alu_controller_host + microsrv_alu_controller_url + self.request_url_map['ms_controller_get_an_lsp'] + req['args']['user_data']['lsp_name']
            pass
        # case 2: get all lsps
        else:
            pass
        print('alu controller:' + self.url)
        pass

    def do_query(self, req, e_need_fresh, e_fresh_suc):
        return super(alu_controller, self).do_query(req, e_need_fresh, e_fresh_suc)

    def form_get_node_request(self, req):

        pass

    def form_del_lsp_request(self, req):
        if ('name' in req['args']):
            self.url += req['args']['name']
            pass
        elif('user_data' in req['args']):
            self.url += req['args']['user_data']['lsp_name']
            pass
        pass

    def form_update_lsp_request(self, req):

        pass

    def form_add_lsp_request(self, req):
        #self.add_lsp_template = {"lspname":"alu_lsp","a":"1","z":"8","hoplist":["1","8"],"bandwidth":"111","subnetwork":"snc1"}
        add_lsp_template = {"lspname":"","a":"","z":"","hoplist":[],"bandwidth":"111","subnetwork":"snc1"}
        # modify add_lsp_dict here
        sub_req = req['args']
        for lsp_key in self.resp_key_map.keys():
            if(lsp_key in req['args'] and self.resp_key_map[lsp_key]):
                if(lsp_key == 'uid'):
                    continue
                elif(lsp_key == 'name'):
                    add_lsp_template['lspname'] = sub_req[lsp_key]
                    pass
                elif(lsp_key == 'from_router_uid'):
                    add_lsp_template['a'] = microsrv_alu_nodename_maps[microsrv_equip_map[sub_req[lsp_key]]['ip_str']]
                    pass
                elif(lsp_key == 'to_router_uid'):
                    add_lsp_template['z'] = microsrv_alu_nodename_maps[microsrv_equip_map[sub_req[lsp_key]]['ip_str']]
                    pass
                elif(lsp_key == 'hop_list'):
                    for list_node in sub_req[lsp_key]:
                        add_lsp_template['hoplist'].append(microsrv_alu_nodename_maps[microsrv_equip_map[list_node]['ip_str']])
                        pass
                    pass
                # add_lsp_dict[self.resp_key_map[lsp_key]] = req[lsp_key]
                # add_lsp_dict[from][address] = sub_req[lsp_key]
                else:
                    exec("%s%s = sub_req[lsp_key]" % ("add_lsp_template", self.resp_key_map[lsp_key]))
                    pass
                pass
        print('alu controller:' + json.dumps(add_lsp_template))
        return json.dumps(add_lsp_template)
        pass

    def form_del_flow_request(self, req):
        #599 why?
        self.useTornado = False
        #{"name":"lsp_alu_lsp_1_4_6_7_5_8_100"}
        sub_req = {"name":""}
        if('user_data' in req['args']):
            if ('from_router_uid' in req['args']['user_data']):
                self.url += microsrv_alu_nodename_maps[microsrv_equip_map[req['args']['user_data']['from_router_uid']]['ip_str']]
                pass
            if ('flow_name' in req['args']['user_data']):
                sub_req['name'] = req['args']['user_data']['flow_name']
        print('alu controller:' + self.url + '/' + json.dumps(sub_req))
        return json.dumps(sub_req)
        pass

    def form_get_flow_request(self, req):
        if ('uid' in req['args']):
            self.url += microsrv_alu_nodename_maps[req['args']['uid']]
        return None
        pass

    def form_add_flow_request(self, req):
        #srcjson:{"args": {"lsp_uid": "xyz123", "flow": {"src": "123.10.88.0/24", "dst": "10.10.20.0/24", "uid": "ips_0"},
        # "user_data": {'lsp_id': '41', 'from_router_uid': 'PE11A', 'lsp_name': 'ALU_S'}}},
        # "request": "ms_controller_add_flow", "ts": "20160718153347", "trans_id": 1468827227}
        #desjson:{"ipv4_src":"10.0.118.0/24","ipv4_dst":"","lspname":"alu_lsp_1_6_7_8"}
        sub_req = {"ipv4_src":"","ipv4_dst":"","lspname":""}
        if ('flow' in req['args']):
            if('src' in req['args']['flow']):
                sub_req['ipv4_src'] = req['args']['flow']['src']
            if('dst' in req['args']['flow']):
                sub_req['ipv4_dst'] = req['args']['flow']['dst']
        if ('user_data' in req['args']):
            if('lsp_name' in req['args']['user_data']):
                sub_req['lspname'] = req['args']['user_data']['lsp_name']
        print('alu controller:' + json.dumps(sub_req))
        return json.dumps(sub_req)
        pass

    @tornado.gen.coroutine
    def process_response(self, resp, req, e_need_fresh, e_fresh_suc):
        print('alu_process_response')
        result = {} #resp.body
        #if fail need resolve here
        if (resp.code < 300):
            result = self.response_process_map[req['request']](resp, req)
            raise tornado.gen.Return(result)
            pass
        else:
            result['err_code'] = resp.code
            result['msg'] = resp.body
            raise tornado.gen.Return(result)
            pass

        pass

    def process_get_lsp_response(self, resp, req):
        #convert to microsvr format
        result = {'lsps':[]}
        if (json.loads(resp.body)['lsplist'].__len__() <= 0):
            return None
        for lsp_item in json.loads(resp.body)['lsplist']:
            try:
                self.lsp_detail = copy.deepcopy(microsrv_lsp_template) #dict copy, different from dict.deepcopy
                for lsp_key in self.resp_key_map.keys():
                    if (self.resp_key_map[lsp_key]):
                        try:
                            if(lsp_key == 'from_router_uid'):
                                self.lsp_detail[lsp_key] = microsrv_equip_loopback_uid_map[microsrv_alu_nodeid_maps[lsp_item['a']]]
                                pass
                            elif(lsp_key == 'to_router_uid'):
                                self.lsp_detail[lsp_key] = microsrv_equip_loopback_uid_map[microsrv_alu_nodeid_maps[lsp_item['z']]]
                                pass
                            elif(lsp_key == 'hop_list'):#ho;pseq
                                for hopitem in json.loads(lsp_item['hopseq']):
                                    self.lsp_detail[lsp_key].append(microsrv_equip_loopback_uid_map[microsrv_alu_nodeid_maps[str(hopitem)]])
                                    pass
                                pass
                            elif(lsp_key == 'status'):
                                self.lsp_detail[lsp_key] = microsrv_lsp_status_map[lsp_item['status']]
                                pass
                            else:
                            # lsp_detail[lsp_key] = eval("%s%s" % (lsp_key, self.resp_key_map[lsp_key]))
                            # x = eval("%s%s" % ("lsp_item", self.resp_key_map[lsp_key]))
                                self.lsp_detail[lsp_key] = eval("%s%s" % ("lsp_item", self.resp_key_map[lsp_key]))
                                pass
                        except:
                            traceback.print_exc()
                        pass
                user_data_content = {"lsp_id":"", "lsp_name":"", "from_router_uid":""}
                user_data_content['lsp_id'] = self.lsp_detail['uid']
                user_data_content['lsp_name'] = self.lsp_detail['name']
                user_data_content['from_router_uid'] = self.lsp_detail['from_router_uid']
                self.lsp_detail['user_data'] = user_data_content
                result['lsps'].append(self.lsp_detail)
                del self.lsp_detail
                pass
            except:
                traceback.print_exc()
            pass
        return result
        pass

    def process_get_node_response(self, resp, req):
        # microsrv_alu_nodename_maps = {"11.11.11.11":"1","12.12.12.12":"2","13.13.13.13":"3","1.1.1.1":"4","3.3.3.3":"5","4.4.4.4":"6","6.6.6.6":"7","21.21.21.21":"8","22.22.22.22":"9","23.23.23.23":"10","14.14.14.14":"11","24.24.24.24":"12"}
        # microsrv_alu_nodeid_maps = {"1":"11.11.11.11","2":"12.12.12.12","3":"13.13.13.13","4":"1.1.1.1","5":"3.3.3.3","6":"4.4.4.4","7":"6.6.6.6","8":"21.21.21.21","9":"22.22.22.22","10":"23.23.23.23","11":"14.14.14.14","12":"24.24.24.24"}
        # {"nodes":[{"ne":"1","name":"PE11_ALU","manage_ip":"11.11.11.11"},{"ne":"2","name":"PE12_JUP","manage_ip":"12.12.12.12"},
        # {"ne":"3","name":"PE13_CIS","manage_ip":"13.13.13.13"},{"ne":"4","name":"R1_CORE","manage_ip":"1.1.1.1"},{"ne":"5","name":"R3_CORE","manage_ip":"3.3.3.3"},
        # {"ne":"6","name":"R4_CORE","manage_ip":"4.4.4.4"},{"ne":"7","name":"CORE_R6","manage_ip":"6.6.6.6"},{"ne":"8","name":"PE21_ALU","manage_ip":"21.21.21.21"},
        # {"ne":"9","name":"PE22_JUP","manage_ip":"22.22.22.22"},{"ne":"10","name":"PE23_CSC","manage_ip":"23.23.23.23"},{"ne":"11","name":"PE14_ZTE","manage_ip":"14.14.14.14"},
        # {"ne":"12","name":"PE24_ZTE","manage_ip":"24.24.24.24"}]}
        resp_body = json.loads(resp.body)
        if(resp_body != None and 'nodes' in resp_body and resp_body['nodes'].__len__() > 0):
            microsrv_alu_nodename_maps.clear()
            microsrv_alu_nodeid_maps.clear()
            for node_item in resp_body['nodes']:
                microsrv_alu_nodename_maps[node_item['manage_ip']] = node_item['ne']
                microsrv_alu_nodeid_maps[node_item['ne']] = node_item['manage_ip']
                pass
        pass

    def process_add_lsp_response(self, resp, req):
        '''
        for lsp create, controller returned is temp status, need get really created status(up)by get_lsp_by_uuid
        1. add time_out(time = 3s) task,params:get_lsp method entry, refresh times, req, resp
        2. if refresh times>15,return get_lsp result to callback
        3. if get_lsp result status change to up, return get_lsp result to callback
        4. lsp create return usr_data(id, name) in order to future delete
        for alu: created--->up
        {"args": {"uid": "14.14.14.14", "from_router_name":"",  "to_router_name": "", "bandwidth": "248", "to_router_uid": "24.24.24.24",
        "from_router_uid": "14.14.14.14",  "hoplist":[], "name": "zte_lsp_14_24_byo"},
        "request": "ms_controller_add_lsp", "ts": "20160601164338", "trans_id": 1464770618}
        '''
        check_req = dict.copy(req)
        check_req['request'] = "ms_controller_get_lsp"
        resp_body = json.loads(resp.body)
        if ('result' in resp_body and resp_body['result'] == 0):
            tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_add_lsp_status_check, 0, check_req, resp)
        else:
            result = {}
            try:
                result['err_code'] = resp_body['result']
                result['msg'] = resp_body['reason']
            except:
                traceback.print_exc()
                pass
            return result
        pass

    def process_del_lsp_response(self, resp, req):
        check_req = dict.copy(req)
        check_req['request'] = "ms_controller_get_lsp"
        resp_body = json.loads(resp.body)
        #{"result":1,"reason":"not name specified lsp existing"}
        if ('result' in resp_body and resp_body['result'] == 0):
            tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_del_lsp_status_check, 0, check_req, resp)
        else:
            result = {}
            try:
                result['err_code'] = resp_body['result']
                result['msg'] = resp_body['reason']
            except:
                traceback.print_exc()
                pass
            return result
        pass

    def process_get_flow_response(self, resp, req):
        return resp.body
        pass

    def process_add_flow_response(self, resp, req):
        check_req = dict.copy(req)
        check_req['request'] = "ms_controller_get_flow"
        resp_body = json.loads(resp.body)
        # resp:
        #{"result":0,"flow":
        # [{"switch":"00:01:00:23:3e:d0:40:98","name":"lsp_alu_lsp_1_6_5_8_104",
        # "cookie":"0","priority":104,"eth_type":"0x0800","actions":"output=1073741912",
        # "active":"true","ipv4_src":"10.0.118.0\/24"}]}
        # microsrv_flow_template = {"flow_src": "", "flow_dst": "", "flow_uid": "","status":1, "user_data": {}}
        if ('result' in resp_body and resp_body['result'] == 0):
            if ('flow' in resp_body and resp_body['flow'].__len__() > 0):
                for flow_item in resp_body['flow']:
                    if('name' in flow_item):
                         check_req['user_data']['flow_id'] = 'flow_' + req['args']['user_data']['lsp_name']
                         check_req['user_data']['flow_name'] = flow_item['name']
                    tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_add_flow_status_check, 0, check_req, resp)
        else:
            result = {}
            try:
                result['err_code'] = resp_body['result']
                result['msg'] = resp_body['reason']
            except:
                traceback.print_exc()
                pass
            return result
        pass

    def process_del_flow_response(self, resp, req):
        check_req = dict.copy(req)
        check_req['request'] = "ms_controller_get_flow"
        resp_body = json.loads(resp.body)
        # microsrv_flow_template = {"flow_src": "", "flow_dst": "", "flow_uid": "","status":1, "user_data": {}}
        if ('result' in resp_body and resp_body['result'] == 0):
            tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_del_flow_status_check, 0, check_req, resp)
        else:
            result = {}
            try:
                result['err_code'] = resp_body['result']
                result['msg'] = resp_body['reason']
            except:
                traceback.print_exc()
                pass
            return result
        pass

    def process_common_response(self, resp, req):
        return {} #resp.body
        pass


class controller_handler(tornado.web.RequestHandler):
    '''
    Main query handler of ms_controller.
    '''
    def initialize(self):
        super(controller_handler, self).initialize()
        # TODO: Add your initialization code here.
        # method map
        # if req_method_map[ms_controller_get_lsp], need all vendors' reqs
        self.req_method_map = {'ms_controller_get_lsp': True,
                           'ms_controller_del_lsp': False,
                           'ms_controller_update_lsp': False,
                           'ms_controller_add_lsp' : False,
                           'ms_controller_del_flow' : False,
                           'ms_controller_get_flow' : False,
                           'ms_controller_add_flow' : False,
                           'ms_controller_set_equips':False}
        pass

    @tornado.gen.coroutine
    def do_all_vendors_req(self, req, e_need_fresh, e_fresh_suc):
        result = {'lsps':[]}
        #juniper
        juniper_ctrler = juniper_controller()
        juniper_ctrler.form_url(req)
        juniper_ctrler.form_method(req)
        juniper_ctrler.form_request(req)
        juniper_result = yield juniper_ctrler.do_query(req, e_need_fresh, e_fresh_suc)
        #zte
        zte_ctrler = zte_controller()
        zte_ctrler.form_url(req)
        zte_ctrler.form_method(req)
        zte_ctrler.form_request(req)
        zte_result = yield zte_ctrler.do_query(req, e_need_fresh, e_fresh_suc)
        #alu
        alu_ctrler = alu_controller()
        alu_ctrler.form_url(req)
        alu_ctrler.form_method(req)
        alu_ctrler.form_request(req)
        alu_result = yield alu_ctrler.do_query(req, e_need_fresh, e_fresh_suc)
        print("alu_result:" + str(alu_result))
        # merge all vendors' result
        if (juniper_result != None and 'lsps' in juniper_result):
            for lsp_item in juniper_result['lsps']:
                result['lsps'].append(lsp_item)
                pass
            pass
        if (zte_result != None and 'lsps' in zte_result):
            for lsp_item in zte_result['lsps']:
                result['lsps'].append(lsp_item)
                pass
            pass
        if (alu_result != None and 'lsps' in alu_result):
            for lsp_item in alu_result['lsps']:
                result['lsps'].append(lsp_item)
                pass
            pass

        raise tornado.gen.Return(result)

    @tornado.gen.coroutine
    def do_dispatch_vendor_req(self, req, e_need_fresh, e_fresh_suc):
        # vendor checker,
        self.controller_vendor_map = {'JUNIPER' : juniper_controller,
                            'CISCO': cisco_controller,
                           'ZTE': zte_controller,
                           'ALU' :alu_controller}
        vendor_name = 'ALU'
        if('from_router_uid' in req['args']):
            vendor_name = microsrv_equip_map[req['args']['from_router_uid']]['vendor']
            pass
        elif('user_data' in req['args']):
            vendor_name = microsrv_equip_map[req['args']['user_data']['from_router_uid']]['vendor']
            pass
        print('xxx:' + vendor_name)
        vendor_ctrler = self.controller_vendor_map[vendor_name]()
        vendor_ctrler.form_url(req)
        vendor_ctrler.form_method(req)
        vendor_ctrler.form_request(req)
        vendor_result = yield vendor_ctrler.do_query(req, e_need_fresh, e_fresh_suc)

        # format result
        result = vendor_result
        raise tornado.gen.Return(result)

    def do_set_equips_request(self, req):
        result = {}
        print(str(req['args']))
        if ('equips' in req['args'] and  req['args']['equips'].__len__() > 0):
            microsrv_equip_map.clear()
            microsrv_equip_loopback_uid_map.clear()
            for equip_item in req['args']['equips']:
                microsrv_equip_map[equip_item['uid']] = equip_item
                microsrv_equip_loopback_uid_map[equip_item['ip_str']] = equip_item['uid']
        print(json.dumps(microsrv_equip_map))
        print(json.dumps(microsrv_equip_loopback_uid_map))
        result['err_code'] = 0
        result['msg'] = 'set equips finished'
        return result
        pass

    def form_response(self, req):
        resp = {'response':req['request'], 'ts':req['ts'], 'trans_id':req['trans_id'], 'err_code':0, 'msg':''}
        return resp

    def get(self):
        self.write('FNDGP')
        return

    @tornado.gen.coroutine
    def post(self):
        try:
            req = json.loads(self.request.body)
            print('<<< ' + str(req))

            #1. Check arguments to decide the controller vendor.
            #2. Instantialize the object
            #3. Use the object to query the controller
            #4. Form response and write to the caller

            if 'request' not in req or req['request'] not in self.req_method_map:
                resp = {}
                resp['err_code'] = -1
                resp['msg'] = 'Unrecognised method'
                self.write(json.dumps(resp))
                self.finish()
                return
            result = None
            if (req['request'] and req['request'] == 'ms_controller_set_equips'):
                self.do_set_equips_request(req)
                pass
            elif (self.req_method_map[req['request']]):
                print('do_all_vendors_req')
                result = yield self.do_all_vendors_req(req, self.application.juniper_need_refresh, self.application.juniper_refresh_suc)
                pass
            else:
                print('do_dispatch_vendor_req')
                result = yield self.do_dispatch_vendor_req(req, self.application.juniper_need_refresh, self.application.juniper_refresh_suc)
                pass
            # ctrler = base_controller()
            # ctrler.form_url(req)
            # ctrler.form_request(req)
            # result = yield ctrler.do_query(req)

            resp = self.form_response(req)
            if (result != None and 'err_code' in result):
                resp['err_code'] = result['err_code']
                resp['msg'] = result['msg']
                pass
            else:
                resp['result'] = result
            print('>>> ' + str(resp))

            self.write(json.dumps(resp))
            self.finish()

        except Exception, data:
            traceback.print_exc()
            print str(Exception) + ':' + str(data)
            self.write('Controller error')
            self.finish()
        pass

@tornado.gen.coroutine
def ms_controller_add_lsp_status_check(times, req, resp):
    times += 1
    # vendor checker,
    controller_vendor_map = {'JUNIPER' : juniper_controller,
                        'CISCO': cisco_controller,
                       'ZTE': zte_controller,
                       'ALU' :alu_controller}
    vendor_name = 'ALU'
    if('from_router_uid' in req['args']):
        vendor_name = microsrv_equip_map[req['args']['from_router_uid']]['vendor']
        pass
    elif('user_data' in req['args']):
        vendor_name = microsrv_equip_map[req['args']['user_data']['from_router_uid']]['vendor']
        pass
    print('xxx:' + vendor_name)
    vendor_ctrler = controller_vendor_map[vendor_name]()
    vendor_ctrler.form_url(req)
    vendor_ctrler.form_method(req)
    vendor_ctrler.form_request(req)
    vendor_result = yield vendor_ctrler.do_query(req, None, None)
    print(vendor_result)

    if (vendor_result != None and 'lsps' in vendor_result and  vendor_result['lsps'].__len__() > 0):
        for lsp_item in vendor_result['lsps']:
            # if status is up or down or missing,return to callback,
            # finish this status check thread
            # elif times == 30, return current status
            if(lsp_item['status'] == microsrv_lsp_status_map['up'] or lsp_item['status'] == microsrv_lsp_status_map['missing'] or
                lsp_item['status'] == microsrv_lsp_status_map['down'] or times == microsrv_status_check_times):
                #return to callback
                print('return to callback')
                request_data = {'request':req['args']['callback'], 'ts':req['ts'], 'trans_id':req['trans_id'], 'args':{}}
                lsp_item['uid'] = req['args']['uid']
                request_data['args'] = lsp_item
                resp = yield vendor_ctrler.do_pure_query(microsrv_te_lsp_man_url,'POST',json.dumps(request_data))
                pass
            # else continue this status check loop
            else:
                tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_add_lsp_status_check, times, req, resp)
                pass
    else:
        #return to callback
        print('return to callback')
        lsp_item = dict.copy(microsrv_lsp_template)
        lsp_item['status'] = microsrv_lsp_status_map['created']
        request_data = {'request':req['args']['callback'], 'ts':req['ts'], 'trans_id':req['trans_id'], 'args':{}}
        lsp_item['uid'] = req['args']['uid']
        request_data['args'] = lsp_item
        resp = yield vendor_ctrler.do_pure_query(microsrv_te_lsp_man_url,'POST',json.dumps(request_data))
        pass

    pass

@tornado.gen.coroutine
def ms_controller_del_lsp_status_check(times, req, resp):
    times += 1
    # vendor checker,
    controller_vendor_map = {'JUNIPER' : juniper_controller,
                        'CISCO': cisco_controller,
                       'ZTE': zte_controller,
                       'ALU' :alu_controller}
    vendor_name = 'ALU'
    if('from_router_uid' in req['args']):
        vendor_name = microsrv_equip_map[req['args']['from_router_uid']]['vendor']
        pass
    elif('user_data' in req['args']):
        vendor_name = microsrv_equip_map[req['args']['user_data']['from_router_uid']]['vendor']
        pass
    print('xxx:' + vendor_name)
    vendor_ctrler = controller_vendor_map[vendor_name]()
    vendor_ctrler.form_url(req)
    vendor_ctrler.form_method(req)
    vendor_ctrler.form_request(req)
    vendor_result = yield vendor_ctrler.do_query(req, None, None)
    print(vendor_result)

    if (vendor_result != None and 'lsps' in vendor_result and  vendor_result['lsps'].__len__() > 0):
        for lsp_item in vendor_result['lsps']:
            # if status is up or down,return to callback,
            # finish this status check thread
            # elif times == 30, return current status
            if(lsp_item['status'] == microsrv_lsp_status_map['removed'] and times != microsrv_status_check_times):
                tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_del_lsp_status_check, times, req, resp)
                pass
            # else continue this status check loop
            else:
                #return to callback
                print('return to callback')
                request_data = {'request':req['args']['callback'], 'ts':req['ts'], 'trans_id':req['trans_id'], 'args':{}}
                lsp_item['uid'] = req['args']['uid']
                request_data['args'] = lsp_item
                resp = yield vendor_ctrler.do_pure_query(microsrv_te_lsp_man_url,'POST',json.dumps(request_data))
                pass
    else:
        #return to callback, tell lsp delete finished
        print('return to callback')
        lsp_item = dict.copy(microsrv_lsp_template)
        lsp_item['status'] = microsrv_lsp_status_map['deleted']
        request_data = {'request':req['args']['callback'], 'ts':req['ts'], 'trans_id':req['trans_id'], 'args':{}}
        lsp_item['uid'] = req['args']['uid']
        request_data['args'] = lsp_item
        resp = yield vendor_ctrler.do_pure_query(microsrv_te_lsp_man_url,'POST',json.dumps(request_data))
        pass

    pass

@tornado.gen.coroutine
def ms_controller_add_flow_status_check(times, req, resp):
    times += 1
    # vendor checker,

    controller_vendor_map = {'JUNIPER' : juniper_controller,
                        'CISCO': cisco_controller,
                       'ZTE': zte_controller,
                       'ALU' :alu_controller}
    vendor_name = 'ALU'
    if('from_router_uid' in req['args']):
        vendor_name = microsrv_equip_map[req['args']['from_router_uid']]['vendor']
        pass
    elif('user_data' in req['args']):
        vendor_name = microsrv_equip_map[req['args']['user_data']['from_router_uid']]['vendor']
        pass
    print('xxx:' + vendor_name)
    vendor_ctrler = controller_vendor_map[vendor_name]()
    '''
    vendor_ctrler.form_url(req)
    vendor_ctrler.form_method(req)
    vendor_ctrler.form_request(req)
    vendor_result = yield vendor_ctrler.do_query(req, None, None)
    print(vendor_result)

    if (vendor_result != None and 'lsps' in vendor_result and  vendor_result['lsps'].__len__() > 0):
        for lsp_item in vendor_result['lsps']:
            # if status is up or down,return to callback,
            # finish this status check thread
            # elif times == 30, return current status
            if(lsp_item['status'] == microsrv_lsp_status_map['up'] or
                lsp_item['status'] == microsrv_lsp_status_map['down'] or times == microsrv_status_check_times):
                #return to callback
                print('return to callback')
                request_data = {'request':req['args']['callback'], 'ts':req['ts'], 'trans_id':req['trans_id'], 'args':{}}
                lsp_item['uid'] = req['args']['uid']
                request_data['args'] = lsp_item
                resp = yield vendor_ctrler.do_pure_query(microsrv_te_flow_man_url,'POST',json.dumps(request_data))
                pass
            # else continue this status check loop
            else:
                tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_add_lsp_status_check, times, req, resp)
                pass
    else:
        #return to callback
        print('return to callback')
        lsp_item = dict.copy(microsrv_lsp_template)
        lsp_item['status'] = microsrv_lsp_status_map['created']
        request_data = {'request':req['args']['callback'], 'ts':req['ts'], 'trans_id':req['trans_id'], 'args':{}}
        lsp_item['uid'] = req['args']['uid']
        request_data['args'] = lsp_item
        resp = yield vendor_ctrler.do_pure_query(microsrv_te_flow_man_url,'POST',json.dumps(request_data))
        pass
    '''
    print('return to callback')
    #microsrv_flow_template = {"flow_src": "", "flow_dst": "", "flow_uid": "","status":1, "user_data": {}}
    flow_item = dict.copy(microsrv_flow_template)
    flow_item['status'] = microsrv_flow_status_map['active']
    request_data = {'request':req['args']['callback'], 'ts':req['ts'], 'trans_id':req['trans_id'], 'args':{}}
    flow_item['flow_uid'] = req['args']['flow']['uid']
    flow_item['user_data'] = req['args']['user_data']
    # flow_item['user_data']['flow_id'] = 'flow_' + req['args']['user_data']['lsp_name']
    # flow_item['user_data']['flow_name'] = 'flow_' + req['args']['user_data']['lsp_name']
    request_data['args'] = flow_item
    resp = yield vendor_ctrler.do_pure_query(microsrv_te_flow_man_url,'POST',json.dumps(request_data))
    pass


@tornado.gen.coroutine
def ms_controller_del_flow_status_check(times, req, resp):
    times += 1
    # vendor checker,

    controller_vendor_map = {'JUNIPER' : juniper_controller,
                        'CISCO': cisco_controller,
                       'ZTE': zte_controller,
                       'ALU' :alu_controller}
    vendor_name = 'ALU'
    if('from_router_uid' in req['args']):
        vendor_name = microsrv_equip_map[req['args']['from_router_uid']]['vendor']
        pass
    elif('user_data' in req['args']):
        vendor_name = microsrv_equip_map[req['args']['user_data']['from_router_uid']]['vendor']
        pass
    print('xxx:' + vendor_name)
    vendor_ctrler = controller_vendor_map[vendor_name]()
    '''
    vendor_ctrler.form_url(req)
    vendor_ctrler.form_method(req)
    vendor_ctrler.form_request(req)
    vendor_result = yield vendor_ctrler.do_query(req, None, None)
    print(vendor_result)

    if (vendor_result != None and 'lsps' in vendor_result and  vendor_result['lsps'].__len__() > 0):
        for lsp_item in vendor_result['lsps']:
            # if status is up or down,return to callback,
            # finish this status check thread
            # elif times == 30, return current status
            if(lsp_item['status'] == microsrv_lsp_status_map['up'] or
                lsp_item['status'] == microsrv_lsp_status_map['down'] or times == microsrv_status_check_times):
                #return to callback
                print('return to callback')
                request_data = {'request':req['args']['callback'], 'ts':req['ts'], 'trans_id':req['trans_id'], 'args':{}}
                lsp_item['uid'] = req['args']['uid']
                request_data['args'] = lsp_item
                resp = yield vendor_ctrler.do_pure_query(microsrv_te_flow_man_url,'POST',json.dumps(request_data))
                pass
            # else continue this status check loop
            else:
                tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(seconds=microsrv_status_check_duration), ms_controller_add_lsp_status_check, times, req, resp)
                pass
    else:
        #return to callback
        print('return to callback')
        lsp_item = dict.copy(microsrv_lsp_template)
        lsp_item['status'] = microsrv_lsp_status_map['created']
        request_data = {'request':req['args']['callback'], 'ts':req['ts'], 'trans_id':req['trans_id'], 'args':{}}
        lsp_item['uid'] = req['args']['uid']
        request_data['args'] = lsp_item
        resp = yield vendor_ctrler.do_pure_query(microsrv_te_flow_man_url,'POST',json.dumps(request_data))
        pass
    '''
    print('return to callback')
    #microsrv_flow_template = {"flow_src": "", "flow_dst": "", "flow_uid": "","status":1, "user_data": {}}
    flow_item = dict.copy(microsrv_flow_template)
    flow_item['status'] = microsrv_flow_status_map['no_scheduled']
    request_data = {'request':req['args']['callback'], 'ts':req['ts'], 'trans_id':req['trans_id'], 'args':{}}
    flow_item['flow_uid'] = req['args']['uid']
    # flow_item['user_data'] = req['args']['user_data']
    # flow_item['user_data']['flow_id'] = "123"
    # flow_item['user_data']['flow_name'] = "22222"
    request_data['args'] = flow_item
    resp = yield vendor_ctrler.do_pure_query(microsrv_te_flow_man_url,'POST',json.dumps(request_data))
    pass

@tornado.gen.coroutine
def juniper_token_refresh(e_need_refresh, e_refresh_suc):
    '''
    POST /oauth2/token HTTP/1.1
    Host: 219.141.189.67:8443
    Authorization: Basic YWRtaW46YWRtaW4xMjM=
    Cache-Control: no-cache
    Postman-Token: af7446d8-9e23-16d0-c1ea-3d4284bb66ea
    Content-Type: application/x-www-form-urlencoded

    grant_type=password&username=admin&password=admin123
    '''
    print('juniper_token_refresh running--')
    ###do zte lsp get for node_id map start
    print('zte lsp get for node_id map init')
    req = {"args": {}, "request": "ms_controller_get_lsp"}
    zte_ctrler = zte_controller()
    zte_ctrler.form_url(req)
    zte_ctrler.form_method(req)
    zte_ctrler.form_request(req)
    result = yield zte_ctrler.do_query(req, None, None)
    ###end
    ###do alu node get for node_name node_id map start
    print('alu nodes get for node_id and node_name map init')
    req = {"args": {}, "request": "ms_controller_get_node"}
    alu_ctrler = alu_controller()
    alu_ctrler.form_url(req)
    alu_ctrler.form_method(req)
    alu_ctrler.form_request(req)
    result = yield alu_ctrler.do_query(req, None, None)
    ###end
    result = False
    while(True):
        yield e_need_refresh.wait()
        token_headers = {'Authorization': 'Basic YWRtaW46YWRtaW4xMjM=', 'Content-Type': 'application/x-www-form-urlencoded', 'Cache-Control': 'no-cache'}
        token_body = 'grant_type=password&username=admin&password=admin123'
        try:
            http_req = tornado.httpclient.HTTPRequest(microsrv_juniper_controller_host + microsrv_juniper_controller_token_url, method = 'POST', body = token_body, headers = token_headers, validate_cert = False)
            client = tornado.httpclient.AsyncHTTPClient()
            resp = yield tornado.gen.Task(client.fetch, http_req)
            print("token refresh:" + str(resp.code) + "/" + str(resp.body))
            # 200/{"access_token":"7w0H2r1zi5P/BSz4nkxcPUZtGWuBMdGHZaWiQQTUQ0c=","token_type":"Bearer"}
            if (resp.code == 200):
                result = True
                resp_body = json.loads(resp.body)
                microsrv_juniper_headers['Authorization'] = resp_body['token_type'] + ' ' + resp_body['access_token']
                pass
        except:
            traceback.print_exc()
            pass
        e_refresh_suc.set()
        e_need_refresh.clear()
        pass
    print('juniper_token_refresh running++')
    raise tornado.gen.Return(result)
    pass

class customer_app(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r'/', controller_handler),
        ]

        settings = {
            'template_path': 'templates',
            'static_path': 'static'
        }

        tornado.web.Application.__init__(self, handlers, **settings)

        # init global thread for juniper token refresh
        self.juniper_need_refresh = tornado.locks.Event()
        self.juniper_refresh_suc = tornado.locks.Event()
        pass

if __name__ == '__main__':
    tornado.options.parse_command_line()
    app = customer_app()
    server = tornado.httpserver.HTTPServer(app)
    server.listen(12727)
    tornado.ioloop.IOLoop.instance().add_timeout(datetime.timedelta(milliseconds=100), juniper_token_refresh, app.juniper_need_refresh, app.juniper_refresh_suc)
    tornado.ioloop.IOLoop.instance().start()
#!/usr/bin/python
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

__author__ = 'chenhg'

from tornado.testing import *
from base_handler import *
import time
import os
import subprocess
driver_serv_cmd = 'coverage run --parallel-mode ms_controller.py'
test_serv_cmd = 'coverage run --parallel-mode test.py'
fake_openo_serv_cmd = 'coverage run --parallel-mode fake_openo.py'
# tunnel_server_cmd = 'coverage run --parallel-mode tunnel_server.py'
# cus_server_cmd = 'coverage run --parallel-mode customer_server.py'
# ms_controller_cmd = 'coverage run --parallel-mode ms_controller.py'
# os.system(command)

driver_prefix_nodes_uri = r'http://127.0.0.1:8670/openoapi/sdno-driver-ct-te/v1/nodes:'
driver_prefix_lsps_uri = r'http://127.0.0.1:8670/openoapi/sdno-driver-ct-te/v1/lsps:'
driver_prefix_flow_policy_uri = r'http://127.0.0.1:8670/openoapi/sdno-driver-ct-te/v1/flow-policy:'
driver_prefix_links_uri = r'http://127.0.0.1:8670/openoapi/sdno-driver-ct-te/v1/links:'

class Test_DriverCT(AsyncTestCase):
    def setUp(self):
        super(Test_DriverCT,self).setUp()
        pass

    def tearDown(self):
        super(Test_DriverCT,self).tearDown()

    @tornado.testing.gen_test
    def test_i_create_link(self):
        print('test_create_link:')
        req_body = {"controller_id": "", "link_parameters": {}}
        code, resp = yield base_handler.do_json_post(driver_prefix_links_uri + 'create-link', req_body)
        self.assertEqual(200, code, 'FAIL:test_create_link')

    @tornado.testing.gen_test
    def test_h_delete_lsp(self):
        print('test_delete_lsp:')
        #req:   {"uid": "46", "user_data": {"lsp_id": "46", "from_router_uid": "PE11A", "lsp_name": "LSP_1-8" }, "callback":"http://127.0.0.1/path"}
        #resp:  {"lsp_uid":0, "lsp_name":"", "status":1}
        req_body = {"uid": "46", "user_data": {"lsp_id": "46", "from_router_uid": "PE14Z", "lsp_name": "lsp_zte" }, "callback":"http://127.0.0.1/path"}
        code, resp = yield base_handler.do_json_post(driver_prefix_lsps_uri + 'get-lsp', req_body)
        self.assertEqual(200, code, 'FAIL:test_delete_lsp')

    @tornado.testing.gen_test
    def test_g_delete_flow_policy(self):
        print('test_delete_flow_policy:')
        #req:   {"uid": "46", "user_data": {"lsp_id": "49", "flow_id": "flow_LSP_rest_1-6-5-8", "from_router_uid": 2, "flow_name": "lsp_LSP_rest_1-6-5-8_100", "lsp_name": "LSP_rest_1-6-5-8"}, "callback":"http://127.0.0.1/path"}
        #resp:  {"flow_src": "", "flow_dst": "", "flow_uid": "","status":1, "user_data": {}}
        req_body = {"uid": "46", "user_data": {"lsp_id": "49", "flow_id": "flow_LSP_rest_1-6-5-8", "from_router_uid": 'PE14Z', "flow_name": "lsp_LSP_rest_1-6-5-8_100", "lsp_name": "LSP_rest_1-6-5-8"}, "callback":"http://127.0.0.1/path"}
        code, resp = yield base_handler.do_json_post(driver_prefix_flow_policy_uri + 'create-flow-policy', req_body)
        self.assertEqual(200, code, 'FAIL:test_delete_flow_policy')

    @tornado.testing.gen_test
    def test_f_get_flow_policy(self):
        print('test_get_flow_policy:')
        #req:   {"uid": "flow_uid", "user_data": {"lsp_id": "49", "flow_id": "flow_LSP_rest_1-6-5-8", "from_router_uid": 2, "flow_name": "lsp_LSP_rest_1-6-5-8_100", "lsp_name": "LSP_rest_1-6-5-8"}}
        req_body = {"uid": "flow_uid", "user_data": {"lsp_id": "49", "flow_id": "flow_LSP_rest_1-6-5-8", "from_router_uid": 'PE14Z', "flow_name": "lsp_LSP_rest_1-6-5-8_100", "lsp_name": "LSP_rest_1-6-5-8"}}
        code, resp = yield base_handler.do_json_post(driver_prefix_flow_policy_uri + 'get-flow-policy', req_body)
        self.assertEqual(200, code, 'FAIL:test_get_flow_policy')

    @tornado.testing.gen_test
    def test_e_create_flow_policy(self):
        print('test_create_flow_policy:')
        #req:   {"flow_name": "", "lsp_uid": "lsp_0", "priority":7, "flow": {"src": "1.2.3.0/24", "dst": "5.6.7.8/24"},"user_data": {'lsp_id': '41', 'from_router_uid': 'PE11A', 'lsp_name': 'ALU_S'}, "callback":"http://127.0.0.1/path"}
        #resp:  {"flow_src": "", "flow_dst": "", "flow_uid": "","status":1, "user_data": {}}
        req_body = {"flow_name": "", "lsp_uid": "lsp_0", "priority":7, "flow": {"src": "1.2.3.0/24", "dst": "5.6.7.8/24"},"user_data": {'lsp_id': '41', 'from_router_uid': 'PE14Z', 'lsp_name': 'lsp_zte'}, "callback":"http://127.0.0.1/path"}
        code, resp = yield base_handler.do_json_post(driver_prefix_flow_policy_uri + 'create-flow-policy', req_body)
        self.assertEqual(200, code, 'FAIL:test_create_flow_policy')

    @tornado.testing.gen_test
    def test_d_get_lsp(self):
        print('test_get_lsp:')
        #req:   {"uid": "46", "user_data": { "lsp_id": "46", "from_router_uid": "PE11A", "lsp_name": "LSP_1-8" }}
        #resp:  [ {"uid": "lsp_0", "from_router_name": "", "to_router_name": "", "bandwidth": "", "to_router_uid": "", "from_router_uid": "PE14Z", "name": "lsp_zte", "hop_list":[], "path":[], "status":1, "priority":7, "delay":"", "user_data":{}} ]
        req_body = {"uid": "46", "user_data": { "lsp_id": "46", "from_router_uid": "PE14Z", "lsp_name": "lsp_zte" }}
        code, resp = yield base_handler.do_json_post(driver_prefix_lsps_uri + 'get-lsp', req_body)
        self.assertEqual(200, code, 'FAIL:test_get_lsp')

    @tornado.testing.gen_test
    def test_c_update_lsp(self):
        print('test_update_lsp:')
        #req:   {"from_router_name": "", "to_router_name": "", "bandwidth": "", "to_router_uid": "", "from_router_uid": "", "callback":"http://127.0.0.1/path", "name": "", "hop_list":[], "priority":7, "delay":""}
        #resp:  {"lsp_uid":0, "lsp_name":"", "status":1}
        req_body = {"uid": "46", "user_data": { "lsp_id": "46", "from_router_uid": "PE14Z", "lsp_name": "LSP_1-8" }, "callback":"http://127.0.0.1/path", "bandwidth":"1000"}
        code, resp = yield base_handler.do_json_post(driver_prefix_lsps_uri + 'update-lsp', req_body)
        self.assertEqual(200, code, 'FAIL:test_update_lsp')

    @tornado.testing.gen_test
    def test_b_create_lsp(self):
        print('test_create_lsp:')
        #req:   {"from_router_name": "", "to_router_name": "", "bandwidth": "", "to_router_uid": "", "from_router_uid": "", "callback":"http://127.0.0.1/path", "name": "", "hop_list":[], "priority":7, "delay":""}
        #resp:  {"lsp_uid":0, "lsp_name":"", "status":1, "user_data":{}}
        req_body = {"from_router_name": "", "to_router_name": "", "bandwidth": "100", "to_router_uid": "PE14Z", "from_router_uid": "PE14Z", "callback":"http://127.0.0.1/path", "name": "lsp_zte", "hop_list":[], "priority":7, "delay":""}
        code, resp = yield base_handler.do_json_post(driver_prefix_lsps_uri + 'create-lsp', req_body)
        self.assertEqual(200, code, 'FAIL:test_create_lsp')

    @tornado.testing.gen_test
    def test_a_set_nodes(self):
        print('test_set_nodes:')
        #req:   {"equips":[{"vendor": "ZTE", "uid": "PE14Z", "pos": "Old village of Gao", "community":"roastedchikenPE14Z", "ip_str": "14.14.14.14", "y": 48.9, "x": 113.8, "model": "aladin", "name": "PE14Z"} ]}
        #resp:  {"err_code":0, "msg":"set equips finished"}
        req_body = {"equips":[{"vendor": "ZTE", "uid": "PE14Z", "pos": "Old village of Gao", "community":"roastedchikenPE14Z", "ip_str": "14.14.14.14", "y": 48.9, "x": 113.8, "model": "aladin", "name": "PE14Z"} ]}
        code, resp = yield base_handler.do_json_post(driver_prefix_nodes_uri + 'set-nodes', req_body)
        self.assertIn('err_code', resp, 'FAIL:test_set_nodes')

if __name__ == '__main__':
    print '---Service Started....'
    # os.system('coverage erase')
    driver_serv = subprocess.Popen(driver_serv_cmd, shell=True)
    test_serv = subprocess.Popen(test_serv_cmd, shell=True)
    fake_serv = subprocess.Popen(fake_openo_serv_cmd, shell=True)
    # tunnel_server = subprocess.Popen(tunnel_server_cmd, shell=True)
    # cus_server = subprocess.Popen(cus_server_cmd, shell=True)
    # ms_controller_server = subprocess.Popen(ms_controller_cmd, shell=True)
    time.sleep(3)
    suite = unittest.TestLoader().loadTestsFromTestCase(Test_DriverCT)
    unittest.TextTestRunner(verbosity=2).run(suite)
    try:
        print '---Service Terminated...'
        sig = 2 #signal.SIGINT
        driver_serv.send_signal(sig)
        test_serv.send_signal(sig)
        fake_serv.send_signal(sig)
        # tunnel_server.send_signal(sig)
        # cus_server.send_signal(sig)
        # ms_controller_server.send_signal(sig)
        print '@@@Service Terminated...'
        pass
    except:
        print '*****Service Terminated...'
        traceback.print_exc()
        pass
    # subprocess.Popen('tskill python & tskill python', shell=True)
    # os.system('coverage combine & coverage html')
    print '+++Service Terminated...'

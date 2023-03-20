# -*- coding: utf-8 -*-
import json

from tornado.ioloop import IOLoop
from tornado.iostream import StreamClosedError
from tornado.tcpclient import TCPClient

from src.objcet import EncryRobot, body_to_encrypted_str, result_encrypted_to_dict


async def app():
    tcp_client = TCPClient()
    stream = await tcp_client.connect('192.168.1.10', 8888)
    # 发送心跳
    # d = {
    #     "cmd": 1,
    #     "req_num": 1,心跳测试
    #     "data": {},
    #     "crc": ""}

    d = {
        "cmd": 2,
        "req_num": 1,
        "data": {"plate": "陕A74110",
                 "plateColor": 0,
                 "entryLane": 2,
                 "exitLane": 2,
                 "entryTime": "20201204120220",
                 "exitTime": "20201204120220",
                 "statisticDate": "20201204",
                 "shift": 2,
                 "fee": 1000,
                 "payNo": "1234567890_101_20200501120000999_100"},  # 扣费测试
        "crc": ""
    }

    # d = {
    #     "cmd": 4,
    #     "req_num": 1,
    #     "data": {
    #         "type": 2,
    #         "date": "20201204",
    #         "shift": 2,
    #         "hour": 11,
    #         "lane": 2,
    #         "devNumber": "TY202010261530"
    #
    #     },  # 对账测试
    #     "crc": ""
    # }

    enc = EncryRobot(encry_class="SM2")
    ciphertext = await body_to_encrypted_str(enc, d)
    stream.write(bytes(json.dumps({"ciphertext": ciphertext}), encoding='utf8'))
    while True:
        msg = await stream.read_bytes(4096, partial=True)
        print(msg)
        s_body = json.loads(str(msg, encoding='utf8'))
        print(s_body)
        s_ciphertext = s_body.get("ciphertext")
        enc = EncryRobot("SM2")
        s_data = await result_encrypted_to_dict(enc, s_ciphertext)
        cmd = s_data.get("cmd")
        c_req_num = s_data.get("req_num")
        if str(cmd) == "0":
            try:
                enc = EncryRobot(encry_class="SM2")
                # ciphertext = await body_to_encrypted_str(enc, d)
                # print(f"xxxxx{ciphertext}")
                # stream.write(bytes(json.dumps({"ciphertext": ciphertext}), encoding='utf8')) #心跳
                print(s_data)

            except StreamClosedError as e:
                stream = await tcp_client.connect('192.168.1.10', 8888)


if __name__ == '__main__':
    loop = IOLoop.current()
    loop.spawn_callback(app)
    loop.start()

# -*- coding: utf-8 -*-

import time
import json
import hmac
import hashlib
import base64
import urllib.parse
from common.conn import http_req
from common.log_msg import logger
from config import DINGTALK_TOKEN, DINGTALK_SECRET


class DingTalkBot(object):
    def __init__(self, task_id, target, statistic=None, services_info=None):
        self.source = 'DingTalkBot'
        self.token = DINGTALK_TOKEN
        self.secret = DINGTALK_SECRET
        self.adder = f'https://oapi.dingtalk.com/robot/send?access_token={self.token}'
        self.task_id = task_id
        self.target = target
        self.statistic = statistic
        self.services_info = services_info
        self.date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())

    def get_autograph(self):
        """
        签名计算代码
        """
        timestamp = str(round(time.time() * 1000))
        secret = self.secret
        secret_enc = secret.encode('utf-8')
        string_to_sign = '{}\n{}'.format(timestamp, secret)
        string_to_sign_enc = string_to_sign.encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        autograph = {'timestamp': timestamp, 'sign': sign}
        return autograph

    def send(self):
        """
        推送钉钉消息
        """
        if not self.token or not self.secret:
            return
        headers = {'Content-Type': 'application/json; charset=utf-8'}
        autograph = self.get_autograph()
        timestamp = autograph['timestamp']
        sign = autograph['sign']
        adder = f'{self.adder}&timestamp={timestamp}&sign={sign}'
        content = {'msgtype': 'markdown',
                   'markdown': {'title': 'Task Monitor',
                                'text': f'#### 消息通知\n\n'
                                        f'**任务目标**: {self.target}\n\n'
                                        f'**任务状态**: 完成\n\n'
                                        f'**任务时间**: {self.date}'
                                }
                   }
        content['markdown']['text'] += f'**资产统计**: \n\n'
        for key, value in self.statistic.items():
            content['markdown']['text'] += f'> {key} -> {value} \n\n'

        content['markdown']['text'] += f'**时间统计**: \n\n'
        for i in self.services_info:
            content['markdown']['text'] += f'> {i}\n\n'

        data = json.dumps(content)

        resp = http_req(adder, method='post', data=data, headers=headers)
        if not resp:
            return

        json_data = json.loads(resp.text)
        if resp.status_code == 200 and json_data['errmsg'] == 'ok':
            return True

    def run(self):
        """
        类执行入口
        """
        try:
            status = self.send()
            if status:
                logger.info(f'source module {self.source} send messages ok')
            else:
                logger.info(f'source module {self.source} send messages error token is not exist or other error over')
                return
        except Exception as e:
            logger.error(f'source module {self.source} send  error info {e} over')
            return


def run(task_id, task_name, _statistic, _services):
    """
    类统一调用入口
    """
    bot = DingTalkBot(task_id, task_name, statistic, services)
    bot.run()


if __name__ == '__main__':
    # 资产数量统计
    statistic = {'site_cnt': 45, 'domain_cnt': 47, 'ip_cnt': 60, 'cert_cnt': 55, 'service_cnt': 8, 'file_leak_cnt': 2,
                 'cip_cnt': 35}
    # 服务耗时统计
    services = [{'name': 'domain_brute', 'elapsed': 0.95}, {'name': 'dns_query_plugin', 'elapsed': 5.79},
                {'name': 'alt_dns', 'elapsed': 14.55},
                {'name': 'port_scan', 'elapsed': 230.29}, {'name': 'ssl_cert', 'elapsed': 3.94},
                {'name': 'find_site', 'elapsed': 10.07},
                {'name': 'fetch_site', 'elapsed': 32.63}, {'name': 'site_identify', 'elapsed': 80.87},
                {'name': 'site_capture', 'elapsed': 93.49},
                {'name': 'file_leak', 'elapsed': 444.94}]

    run('65a800000e612159ff6385e2', '自动化测试4', statistic, services)

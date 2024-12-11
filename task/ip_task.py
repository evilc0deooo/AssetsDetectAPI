# -*- coding: utf-8 -*-

import thirdparty
import time
from IPy import IP
from bson import ObjectId
from common.mongo import conn_db
from services import fetch_cert
from services.nmap_scan import run as nmap_scan
from services.check_http import run as check_http
from task.common_task import CommonTask, BaseUpdateTask, WebSiteFetch
from config import TOP_10, TOP_100, TOP_1000
from common.log_msg import logger
from utils.ip import not_in_black_ips, get_ip_type, get_ip_asn, get_ip_city


def ssl_cert(ip_info_list):
    try:
        targets = []
        for ip_info in ip_info_list:
            for port_info in ip_info['port_info']:
                if port_info['port_id'] == 80:
                    continue
                targets.append('{}:{}'.format(ip_info['ip'], port_info['port_id']))

        f = fetch_cert.SSLCert(targets)
        return f.run()
    except Exception as e:
        logger.exception(e)

    return {}


class IPTask(CommonTask):
    def __init__(self, ip_target=None, task_id=None, options=None):
        super().__init__(task_id=task_id)

        self.ip_target = ip_target
        self.task_id = task_id
        self.options = options
        self.ip_info_list = []
        self.ip_set = set()
        self.site_list = []
        self.cert_map = {}
        self.service_info_list = []

        # 用来区分是正常任务
        self.task_tag = 'task'
        self.base_update_task = BaseUpdateTask(self.task_id)

    def port_scan(self):
        scan_port_map = {
            'test': TOP_10,
            'top100': TOP_100,
            'top1000': TOP_1000,
            'all': '0-65535',
            'custom': self.options.get('port_custom', '80,443')
        }
        option_scan_port_type = self.options.get("port_scan_type", "test")
        scan_port_option = {
            'ports': scan_port_map.get(option_scan_port_type, TOP_10),
            'service_detect': self.options.get('service_detection', False),
            'os_detect': self.options.get('os_detection', False),
            'port_parallelism': self.options.get('port_parallelism', 32),  # 探测报文并行度
            'port_min_rate': self.options.get('port_min_rate', 64),  # 最少发包速率
            'custom_host_timeout': None,  # 主机超时时间（s）
        }
        # 只有当设置为自定义时才会去设置超时时间
        if self.options.get('host_timeout_type') == 'custom':
            scan_port_option['custom_host_timeout'] = self.options.get('host_timeout', 60 * 15)

        targets = self.ip_target.split()
        ip_port_result = nmap_scan(targets, **scan_port_option)
        if not ip_port_result:
            return
        self.ip_info_list.extend(ip_port_result)
        for ip_info in ip_port_result:
            curr_ip = ip_info['ip']
            self.ip_set.add(curr_ip)
            if not not_in_black_ips(curr_ip):
                continue

            ip_info['task_id'] = self.task_id
            ip_info['ip_type'] = get_ip_type(curr_ip)
            ip_info['geo_asn'] = {}
            ip_info['geo_city'] = {}

            if ip_info['ip_type'] == 'PUBLIC':
                ip_info['geo_asn'] = get_ip_asn(curr_ip)
                ip_info['geo_city'] = get_ip_city(curr_ip)

            # 仅仅资产发现任务将 IP 全部存储起来
            if self.task_tag == 'task':
                conn_db('ip').insert_one(ip_info)

    def find_site(self):
        url_temp_list = []
        for ip_info in self.ip_info_list:
            for port_info in ip_info['port_info']:
                curr_ip = ip_info['ip']
                port_id = port_info['port_id']
                if port_id == 80:
                    url_temp = f'http://{curr_ip}'
                    url_temp_list.append(url_temp)
                    continue

                if port_id == 443:
                    url_temp = f'https://{curr_ip}'
                    url_temp_list.append(url_temp)
                    continue

                url_temp1 = f'http://{curr_ip}:{port_id}'
                url_temp2 = f'https://{curr_ip}:{port_id}'
                url_temp_list.append(url_temp1)
                url_temp_list.append(url_temp2)

        check_map = check_http(url_temp_list)
        # 去除 https 和 http 相同的资产
        alive_site = []
        for x in check_map:
            if x.startswith('https://'):
                alive_site.append(x)

            elif x.startswith('http://'):
                x_temp = 'https://' + x[7:]
                if x_temp not in check_map:
                    alive_site.append(x)

        self.site_list.extend(alive_site)

    def ssl_cert(self):
        if self.options.get('port_scan'):
            self.cert_map = ssl_cert(self.ip_info_list)
        else:
            self.cert_map = ssl_cert(self.ip_set)

        for target in self.cert_map:
            if ':' not in target:
                continue
            ip = target.split(':')[0]
            port = int(target.split(":")[1])
            item = {
                'ip': ip,
                'port': port,
                'cert': self.cert_map[target],
                'task_id': self.task_id,
            }
            conn_db('cert').insert_one(item)

    def save_service_info(self):
        self.service_info_list = []
        services_list = set()
        for _data in self.ip_info_list:
            port_info_list = _data.get('port_info')
            for _info in port_info_list:
                if _info.get('service_name'):
                    if _info.get('service_name') not in services_list:
                        _result = {'service_name': _info.get('service_name'), 'service_info': []}
                        _result['service_info'].append({'ip': _data.get('ip'),
                                                        'port_id': _info.get('port_id'),
                                                        'product': _info.get('product'),
                                                        'version': _info.get('version')})
                        _result['task_id'] = self.task_id
                        self.service_info_list.append(_result)
                        services_list.add(_info.get('service_name'))
                    else:
                        for service_info in self.service_info_list:
                            if service_info.get('service_name') == _info.get('service_name'):
                                service_info['service_info'].append({'ip': _data.get('ip'),
                                                                     'port_id': _info.get('port_id'),
                                                                     'product': _info.get('product'),
                                                                     'version': _info.get('version')})
        if self.service_info_list:
            conn_db('service').insert_many(self.service_info_list)

    def gen_cip_map(self):
        task_id = self.task_id
        query = dict()
        if isinstance(task_id, str) and len(task_id) == 24:
            query['task_id'] = task_id

        results = list(conn_db('ip').find(query, {'ip': 1, 'domain': 1}))
        cip_map = dict()
        for result in results:
            if result.get('domain') is None:
                continue

            cip = result['ip'] + '/24'
            cip = IP(cip, make_net=True).strNormal(1)
            count_map = cip_map.get(cip)
            if count_map is None:
                cip_map[cip] = {
                    'domain_set': set(result['domain']),
                    'ip_set': {result['ip']}
                }
            else:
                count_map['domain_set'] |= set(result['domain'])
                count_map['ip_set'] |= {result['ip']}

        return cip_map

    def insert_cip_stat(self):
        """
        统计 CIDR 入库
        """
        cip_map = self.gen_cip_map()
        logger.info(f'insert cip stat {len(cip_map)}')

        for cidr_ip in cip_map:
            item = cip_map[cidr_ip]
            ip_list = list(item['ip_set'])
            domain_list = list(item['domain_set'])

            data = {
                'cidr_ip': cidr_ip,
                'ip_count': len(ip_list),
                'ip_list': ip_list,
                'domain_count': len(domain_list),
                'domain_list': domain_list,
                'task_id': self.task_id
            }

            conn_db('cip').insert_one(data)

    def task_statistic(self):
        """
        对任务中的资产信息进行统计
        """
        query = dict()
        task_id = self.task_id
        if isinstance(task_id, str) and len(task_id) == 24:
            query['task_id'] = task_id

        ret = dict()
        table_list = ['site', 'domain', 'ip', 'cert', 'service', 'file_leak', 'cip']
        for table in table_list:
            cnt = conn_db(table).count_documents(query)
            stat_key = table + '_cnt'
            ret[stat_key] = cnt

        return ret

    def insert_task_stat(self):
        """
        插入资产信息统计结果
        """
        query = {
            '_id': ObjectId(self.task_id)
        }
        stat = self.task_statistic()
        logger.info('insert task statistic')
        update = {'$set': {'statistic': stat}}
        conn_db('task').update_one(query, update)

    def run(self):
        """
        任务开始
        """
        base_update = self.base_update_task
        base_update.update_task_field('start_time', thirdparty.curr_date(time.time()))

        # 端口扫描开始
        if self.options.get('port_scan'):
            base_update.update_task_field('status', 'port_scan')
            t1 = time.time()
            self.port_scan()
            elapse = time.time() - t1
            base_update.update_services('port_scan', elapse)

        # 存储服务信息
        if self.options.get('service_detection'):
            self.save_service_info()

        # 证书获取开始
        if self.options.get('ssl_cert'):
            base_update.update_task_field('status', 'ssl_cert')
            t1 = time.time()
            self.ssl_cert()
            elapse = time.time() - t1
            base_update.update_services('ssl_cert', elapse)

        base_update.update_task_field('status', 'find_site')
        t1 = time.time()
        self.find_site()
        elapse = time.time() - t1
        base_update.update_services('find_site', elapse)

        web_site_fetch = WebSiteFetch(task_id=self.task_id, sites=self.site_list, options=self.options)
        web_site_fetch.run()

        # 加上统计信息
        self.insert_cip_stat()

        self.task_statistic()
        self.insert_task_stat()

        # 任务结束
        base_update.update_task_field('status', 'done')
        base_update.update_task_field('end_time', thirdparty.curr_date(time.time()))


def ip_task(ip_target, task_id, options):
    d = IPTask(ip_target=ip_target, task_id=task_id, options=options)
    try:
        d.run()
    except Exception as e:
        logger.exception(e)
        d.base_update_task.update_task_field('status', 'error')

# -*- coding: utf-8 -*-

import time
import thirdparty
from bson import ObjectId
from IPy import IP
from utils.cdn import get_cdn_name_by_ip
from utils.ip import IPInfo
from common.mongo import conn_db
from utils.domain import domain_parsed
from utils.domain import not_found_domain_ips
from utils.domain import get_cname, get_ip, get_fld
from utils.domain import check_domain_black
from services.resolver import DomainInfo
from task.common_task import CommonTask, ssl_cert
from task.common_task import WebSiteFetch
from task.common_task import find_site
from services.domain_brute import run as domain_brute
from services.dns_search import run_query_plugin
from services.alt_dns import run as alt_dns
from services.build_domain_info import run as build_domain_info
from services.port_scan import run as port_scan
from services.probe_http import run as probe_http
from config import DOMAIN_DICT_2W, DOMAIN_DICT_TEST
from config import TOP_10, TOP_100, TOP_1000
from common.log_msg import logger


class DomainTask(CommonTask):
    """
    域名任务流程
    """

    def __init__(self, base_domain=None, task_id=None, options=None):
        super().__init__(task_id=task_id)
        self.base_domain = base_domain
        self.task_id = task_id
        self.options = options
        self.domain_info_list = []
        self.ip_info_list = []
        self.ip_set = set()
        self.site_list = []
        self.record_map = {}
        self.ipv4_map = {}
        self.cert_map = {}
        self.service_info_list = []

        # 用来区分是正常任务
        self.task_tag = 'task'

        self.web_site_fetch = None

    def update_task_field(self, field=None, value=None):
        """
        更新任务状态字段
        """
        query = {'_id': ObjectId(self.task_id)}
        update = {'$set': {field: value}}
        conn_db('task').update_one(query, update)

    def update_services(self, services, elapsed):
        """
        实时显示当前阶段任务状态
        """
        elapsed = f'{elapsed:.2f}'
        self.update_task_field('status', services)
        query = {'_id': ObjectId(self.task_id)}
        update = {'$push': {'service': {'name': services, 'elapsed': float(elapsed)}}}
        conn_db('task').update_one(query, update)

    def save_domain_info_list(self, domain_info_list, source_name='domain_brute'):
        """
        保存域名爆破信息到数据库
        """
        for domain_info_obj in domain_info_list:
            domain_info = domain_info_obj.dump_json(flag=False)
            domain_info['task_id'] = self.task_id
            domain_info['source'] = source_name

            _domain_parsed = domain_parsed(domain_info['domain'])
            if _domain_parsed:
                domain_info['fld'] = _domain_parsed['fld']
            conn_db('domain').insert_one(domain_info)

    def domain_brute(self):
        word_file = DOMAIN_DICT_2W
        if self.options.get('domain_brute_type') == 'test':
            word_file = DOMAIN_DICT_TEST
        # 调用工具去进行域名爆破，如果存在泛解析，会把包含泛解析 IP 的域名给删除
        domain_info_list = domain_brute(self.base_domain, word_file=word_file,
                                        wildcard_domain_ip=not_found_domain_ips(self.base_domain))

        domain_info_list = self.clear_domain_info_by_record(domain_info_list)
        domain_info_list = list(set(domain_info_list))
        if self.task_tag == 'task':
            self.domain_info_list.extend(domain_info_list)
            self.save_domain_info_list(domain_info_list, source_name='domain_brute')

    def clear_domain_info_by_record(self, domain_info_list):
        """
        根据 record 记录清除泛解析域名
        """
        MAX_MAP_COUNT = 35
        new_list = []
        for info in domain_info_list:
            if not info.record_list:
                continue

            record = info.record_list[0]
            ip = info.ip_list[0]

            # 解决泛解析域名问题，果断剔除
            if ip in not_found_domain_ips(self.base_domain):
                continue

            cnt = self.record_map.get(record, 0)
            cnt += 1
            # 如果解析记录超过 35 次相同判断为泛解析域名
            self.record_map[record] = cnt
            if cnt > MAX_MAP_COUNT:
                continue

            new_list.append(info)

        return new_list

    def dns_query_plugin(self):
        """
        run_query_plugin
        """
        logger.info(f'start run dns_query_plugin {self.base_domain}')
        results = run_query_plugin(self.base_domain)
        sources_map = dict()
        for result in results:
            subdomains = result['subdomains']
            source = result['source']
            sources_map[source] = subdomains

        cnt = 0  # 统计真实数据
        for source in sources_map:
            source_domains = sources_map[source]
            if not source_domains:
                continue

            logger.info(f'start build domain info, source: {source}')
            domain_info_list = build_domain_info(source_domains)
            domain_info_list = list(set(domain_info_list))
            if self.task_tag == 'task':
                # 添加选项是否跳过域名泛解析，只针对 DNS 子域名收集接口
                if self.options.get('skip_not_found_domain'):
                    domain_info_list = self.clear_domain_info_by_record(domain_info_list)

                self.save_domain_info_list(domain_info_list, source_name=source)

            cnt += len(domain_info_list)
            self.domain_info_list.extend(domain_info_list)

        logger.info(f'end run dns_query_plugin {self.base_domain}, result {len(results)}, real result: {cnt}')

    def alt_dns_current(self):
        primary_domain = get_fld(self.base_domain)
        # 当前下发的是主域名就跳过
        if primary_domain == self.base_domain or primary_domain == '':
            return []
        fake = {
            'domain': self.base_domain,
            'type': 'CNAME',
            'record': [],
            'ips': []
        }
        fake_info = DomainInfo(**fake)
        logger.info(f'alt_dns_current {self.base_domain}, primary_domain:{primary_domain}')

        data = alt_dns([fake_info], primary_domain, wildcard_domain_ip=not_found_domain_ips(self.base_domain))

        return data

    def build_domain_info(self, domains):
        """
        构建 domain_info_list 带去重功能
        """
        fake_list = []
        domains_set = set()
        for item in domains:
            domain = item
            if isinstance(item, dict):
                domain = item['domain']

            domain = domain.lower().strip()
            if domain in domains_set:
                continue
            domains_set.add(domain)

            if check_domain_black(domain):
                continue

            fake = {
                'domain': domain,
                'type': 'CNAME',
                'record': [],
                'ips': []
            }
            fake_info = DomainInfo(**fake)
            if fake_info not in self.domain_info_list:
                fake_list.append(fake_info)

        domain_info_list = build_domain_info(fake_list)

        return domain_info_list

    def alt_dns(self):
        """
        alt_dns 智能组合域名
        """
        if len(self.domain_info_list) > 300 and len(not_found_domain_ips(self.base_domain)) > 0:
            # 目标为泛解析域名并且泛解析子域名大于 300 则跳过执行 alt_dns
            logger.warning(
                f'{self.base_domain} domain name pan resolution, and domain_info_list {len(self.domain_info_list)} > 300, skip alt_dns')
            return

        alt_dns_current_out = self.alt_dns_current()
        alt_dns_out = alt_dns(self.domain_info_list, self.base_domain,
                              wildcard_domain_ip=not_found_domain_ips(self.base_domain))
        alt_dns_out.extend(alt_dns_current_out)
        if len(alt_dns_out) <= 0:
            return

        alt_domain_info_list = self.build_domain_info(alt_dns_out)
        if self.task_tag == 'task':
            alt_domain_info_list = self.clear_domain_info_by_record(alt_domain_info_list)
            logger.info(f'alt_dns real result:{len(alt_domain_info_list)}')
            if len(alt_domain_info_list) > 0:
                self.save_domain_info_list(alt_domain_info_list, source_name='alt_dns')

        self.domain_info_list.extend(alt_domain_info_list)

    def build_single_domain_info(self):
        _type = 'A'
        cname = get_cname(self.base_domain)
        if cname:
            _type = 'CNAME'
        ips = get_ip(self.base_domain)
        if _type == 'A':
            record = ips
        else:
            record = cname

        if not ips:
            return

        item = {
            'domain': self.base_domain,
            'type': _type,
            'record': record,
            'ips': ips
        }

        return DomainInfo(**item)

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

    def domain_fetch(self):
        """
        域名爆破开始
        """
        if self.options.get('domain_brute'):
            self.update_task_field('status', 'domain_brute')
            t1 = time.time()
            self.domain_brute()
            elapse = time.time() - t1
            self.update_services('domain_brute', elapse)
        else:
            domain_info = self.build_single_domain_info()
            if domain_info:
                self.domain_info_list.append(domain_info)
                self.save_domain_info_list([domain_info])

        if '{fuzz}' in self.base_domain:
            return

        # 批量执行域名接口查询插件
        if self.options.get('dns_query_plugin'):
            self.update_task_field('status', 'dns_query_plugin')
            t1 = time.time()
            self.dns_query_plugin()
            elapse = time.time() - t1
            self.update_services('dns_query_plugin', elapse)

        # 智能域名生成
        if self.options.get('alt_dns'):
            self.update_task_field('status', 'alt_dns')
            t1 = time.time()
            self.alt_dns()
            elapse = time.time() - t1
            self.update_services('alt_dns', elapse)

        # 临时对域名信息去重，数据库内数据未进行去重
        self.domain_info_list = list(set(self.domain_info_list))

    def gen_ipv4_map(self):
        ipv4_map = {}
        for domain_info in self.domain_info_list:
            for ip in domain_info.ip_list:
                old_domain = ipv4_map.get(ip, set())
                old_domain.add(domain_info.domain)
                ipv4_map[ip] = old_domain
                self.ip_set.add(ip)

        self.ipv4_map = ipv4_map

    def port_scan(self):
        """
        端口扫描
        """
        scan_port_map = {
            'top10': TOP_10,
            'top100': TOP_100,
            'top1000': TOP_1000,
            'all': '0-65535',
            'custom': self.options.get('port_custom', '80,443')
        }

        option_scan_port_type = self.options.get('port_scan_type', 'test')
        scan_port_option = {
            'ports': scan_port_map.get(option_scan_port_type, TOP_10),
            'service_detect': self.options.get('service_detection', False),
            'os_detect': self.options.get('os_detection', False),
            'skip_scan_cdn_ip': self.options.get('skip_scan_cdn_ip', False),  # 跳过扫描 CDN IP
            'port_parallelism': self.options.get('port_parallelism', 32),  # 探测报文并行度
            'port_min_rate': self.options.get('port_min_rate', 64),  # 最少发包速率
            'custom_host_timeout': None  # 主机超时时间（s）
        }

        # 只有当设置为自定义时才会去设置超时时间
        if self.options.get('host_timeout_type') == 'custom':
            scan_port_option['custom_host_timeout'] = self.options.get('host_timeout', 60 * 15)

        ip_info_list = port_scan(self.domain_info_list, scan_port_option)
        for ip_info_obj in ip_info_list:
            ip_info = ip_info_obj.dump_json(flag=False)
            ip_info['task_id'] = self.task_id
            conn_db('ip').insert_one(ip_info)

        self.ip_info_list.extend(ip_info_list)

    def ssl_cert(self):
        """
        获取 SSL Cert 证书
        """
        if self.options.get('port_scan'):
            self.cert_map = ssl_cert(self.ip_info_list, self.base_domain)
        else:
            self.cert_map = ssl_cert(self.ip_set, self.base_domain)

        for target in self.cert_map:
            if ':' not in target:
                continue
            ip = target.split(':')[0]
            port = int(target.split(':')[1])
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
            port_info_list = _data.port_info_list
            for _info in port_info_list:
                if _info.service_name:
                    if _info.service_name not in services_list:
                        _result = {'service_name': _info.service_name, "service_info": []}
                        _result['service_info'].append({'ip': _data.ip,
                                                        'port_id': _info.port_id,
                                                        'product': _info.product,
                                                        'version': _info.version})
                        _result['task_id'] = self.task_id
                        self.service_info_list.append(_result)
                        services_list.add(_info.service_name)
                    else:
                        for service_info in self.service_info_list:
                            if service_info.get('service_name') == _info.service_name:
                                service_info['service_info'].append({'ip': _data.ip,
                                                                     'port_id': _info.port_id,
                                                                     'product': _info.product,
                                                                     'version': _info.version})
        if self.service_info_list:
            conn_db('service').insert_many(self.service_info_list)

    def save_ip_info(self):
        """
        保存没有开放端口的 IP address
        """
        fake_ip_info_list = []
        for ip in self.ipv4_map:
            data = {
                'ip': ip,
                'domain': list(self.ipv4_map[ip]),
                'port_info': [],
                'os_info': {},
                'cdn_name': get_cdn_name_by_ip(ip)
            }
            info_obj = IPInfo(**data)
            if info_obj not in self.ip_info_list:
                fake_ip_info_list.append(info_obj)

        for ip_info_obj in fake_ip_info_list:
            ip_info = ip_info_obj.dump_json(flag=False)
            ip_info['task_id'] = self.task_id
            conn_db('ip').insert_one(ip_info)

    def start_ip_fetch(self):
        self.gen_ipv4_map()

        """ 开始端口扫描 """
        if self.options.get('port_scan'):
            self.update_task_field('status', 'port_scan')
            t1 = time.time()
            self.port_scan()
            elapse = time.time() - t1
            self.update_services('port_scan', elapse)

        """ 开始证书获取 """
        if self.options.get('ssl_cert'):
            self.update_task_field('status', 'ssl_cert')
            t1 = time.time()
            self.ssl_cert()
            elapse = time.time() - t1
            self.update_services('ssl_cert', elapse)

        # 服务信息存储
        if self.options.get('service_detection'):
            self.save_service_info()
        self.save_ip_info()

    def find_site(self):
        if self.options.get('port_scan'):
            # 根据端口扫描结果寻找站点
            sites = find_site(self.ip_info_list)
            # 实战遇到端口扫描被 WAF 拦截结果为空的情况
            if not sites:
                sites = probe_http(self.domain_info_list)
        else:
            sites = probe_http(self.domain_info_list)
        self.site_list.extend(sites)

    def start_site_fetch(self):
        self.update_task_field('status', 'find_site')
        t1 = time.time()
        self.find_site()
        elapse = time.time() - t1
        self.update_services('find_site', elapse)
        web_site_fetch = WebSiteFetch(task_id=self.task_id, sites=self.site_list, options=self.options)
        web_site_fetch.run()

        self.web_site_fetch = web_site_fetch

    def run(self):
        """
        任务开始
        """
        self.update_task_field('start_time', thirdparty.curr_date(time.time()))
        self.domain_fetch()
        self.start_ip_fetch()
        self.start_site_fetch()
        self.insert_cip_stat()
        self.insert_task_stat()

        # 任务结束
        self.update_task_field('status', 'done')
        self.update_task_field('end_time', thirdparty.curr_date(time.time()))


def domain_task(base_domain, task_id, options):

    d = DomainTask(base_domain=base_domain, task_id=task_id, options=options)
    try:
        d.run()
    except Exception as e:
        logger.exception(e)
        d.update_task_field('status', 'error')
        d.update_task_field('end_time', thirdparty.curr_date(time.time()))

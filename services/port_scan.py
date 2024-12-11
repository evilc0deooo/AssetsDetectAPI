# -*- coding: utf-8 -*-

import time
import copy
from typing import cast, List, Dict, Any
from config import TOP_10
from common.log_msg import logger
from services.nmap_scan import run as nmap_scan
from utils.cdn import get_cdn_name_by_ip, get_cdn_name_by_cname
from utils.domain import DomainInfo
from utils.ip import PortInfo, IPInfo


class PortScan(object):
    """
    端口扫描
    """

    def __init__(self, domain_info_list, option):
        self.domain_info_list = domain_info_list
        self.ipv4_map = {}
        self.ip_cdn_map = {}
        self.have_cdn_ip_list = []
        self.skip_scan_cdn_ip = False

        if option is None:
            option = {
                'ports': TOP_10,
                'service_detect': False,
                'os_detect': False,
                'port_parallelism': 32,
                'port_min_rate': 64,
                'custom_host_timeout': None
            }

        if 'skip_scan_cdn_ip' in option:
            self.skip_scan_cdn_ip = option['skip_scan_cdn_ip']

        del option['skip_scan_cdn_ip']

        self.option = option

    @staticmethod
    def get_cdn_name(ip, domain_info):
        """
        识别判断 CDN 信息
        """
        cdn_name = get_cdn_name_by_ip(ip)
        if cdn_name:
            return cdn_name

        if domain_info.type != 'CNAME':
            return ''

        if not domain_info.record_list:
            return ''

        cname = domain_info.record_list[0]
        # 通过 CNAME 判断是否为 CDN
        cdn_name = get_cdn_name_by_cname(cname)
        if cdn_name:
            return cdn_name

        if len(domain_info.ip_list) >= 4:
            return 'CDN'

        return ''

    def run(self):
        for info in self.domain_info_list:
            for ip in info.ip_list:
                old_domain = self.ipv4_map.get(ip, set())
                old_domain.add(info.domain)
                self.ipv4_map[ip] = old_domain

                if ip not in self.ip_cdn_map:
                    cdn_name = self.get_cdn_name(ip, info)  # 识别 CDN
                    self.ip_cdn_map[ip] = cdn_name
                    if cdn_name:
                        self.have_cdn_ip_list.append(ip)

        all_ipv4_list = self.ipv4_map.keys()
        # 判断是否跳过 CDN IP
        if self.skip_scan_cdn_ip:
            all_ipv4_list = list(set(all_ipv4_list) - set(self.have_cdn_ip_list))

        start_time = time.time()
        logger.info(f'start port_scan {len(all_ipv4_list)}')
        ip_port_result = []
        if all_ipv4_list:
            # 调用 nmap 模块进行端口扫描
            ip_port_result = nmap_scan(all_ipv4_list, **self.option)
            elapse = time.time() - start_time
            logger.info(f'end port_scan result {len(ip_port_result)}, elapse {elapse}')

        ip_info_obj = []
        for result in ip_port_result:
            curr_ip = result['ip']
            result['domain'] = list(self.ipv4_map[curr_ip])
            result['cdn_name'] = self.ip_cdn_map.get(curr_ip, '')

            port_info_obj_list = []
            for port_info in result['port_info']:
                port_info_obj_list.append(PortInfo(**port_info))

            # 应为类型 'list[dict[str, Any]]'，但实际为 'list[PortInfo]'
            # result['port_info'] = port_info_obj_list
            result['port_info'] = cast(List[Dict[str, Any]], port_info_obj_list)
            ip_info_obj.append(IPInfo(**result))

        if self.skip_scan_cdn_ip:
            fake_cdn_ip_info = self.build_fake_cdn_ip_info()
            ip_info_obj.extend(fake_cdn_ip_info)

        return ip_info_obj

    def build_fake_cdn_ip_info(self):
        ret = []
        map_80_port = {
            'port_id': 80,
            'service_name': 'http',
            'version': '',
            'protocol': 'tcp',
            'product': ''
        }
        fake_80_port = PortInfo(**map_80_port)

        map_443_port = {
            'port_id': 443,
            'service_name': 'https',
            'version': '',
            'protocol': 'tcp',
            'product': ''
        }
        fake_443_port = PortInfo(**map_443_port)
        fake_port_info = [fake_80_port, fake_443_port]

        for ip in self.ip_cdn_map:
            cdn_name = self.ip_cdn_map[ip]
            if not cdn_name:
                continue

            item = {
                'ip': ip,
                'domain': list(self.ipv4_map[ip]),
                'port_info': copy.deepcopy(fake_port_info),
                'cdn_name': cdn_name,
                'os_info': {}

            }
            ret.append(IPInfo(**item))

        return ret


def run(domain_info_list, option=None):
    """
    类统一调用入口
    """
    s = PortScan(domain_info_list, option)
    return s.run()

# -*- coding: utf-8 -*-

from utils import nmap
from config import TOP_10
from common.log_msg import logger
from utils.ip import not_in_black_ips


class NmapScan(object):
    def __init__(self, targets, ports=None, service_detect=False, os_detect=False, port_parallelism=None,
                 port_min_rate=None, custom_host_timeout=None):
        self.targets = ' '.join(targets)
        self.ports = ports
        self.max_hostgroup = 128
        self.alive_port = '22,80,443,843,3389,8007-8011,8443,9090,8080-8091,8093,8099,5000-5004,2222,3306,1433,21,25'
        self.nmap_arguments = '-sT -n --open'
        self.max_retries = 3
        self.host_timeout = 60 * 5
        self.parallelism = port_parallelism  # 默认 32
        self.min_rate = port_min_rate  # 默认 64

        if service_detect:
            self.host_timeout += 60 * 5
            self.nmap_arguments += ' -sV'

        if os_detect:
            self.host_timeout += 60 * 4
            self.nmap_arguments += ' -O'

        if len(self.ports.split(',')) > 60:
            self.nmap_arguments += f' -PE -PS{self.alive_port}'
            self.max_retries = 2
        else:
            if self.ports != '0-65535':
                self.nmap_arguments += ' -Pn'

        if self.ports == '0-65535':
            self.max_hostgroup = 8
            self.min_rate = max(self.min_rate, 150)

            self.nmap_arguments += f' -PE -PS{self.alive_port}'
            self.host_timeout += 60 * 5
            self.max_retries = 2

        self.nmap_arguments += ' --max-rtt-timeout 800ms'
        self.nmap_arguments += f' --min-rate {self.min_rate}'
        self.nmap_arguments += ' --script-timeout 6s'
        self.nmap_arguments += f' --max-hostgroup {self.max_hostgroup}'

        # 依据传过来的超时为准
        if custom_host_timeout is not None:
            if int(custom_host_timeout) > 0:
                self.host_timeout = custom_host_timeout
        self.nmap_arguments += f' --host-timeout {self.host_timeout}s'
        self.nmap_arguments += f' --min-parallelism {self.parallelism}'
        self.nmap_arguments += f' --max-retries {self.max_retries}'

    def run(self):
        logger.info(f'nmap target {self.targets[:20]}  ports {self.ports[:20]}  arguments {self.nmap_arguments}')
        nm = nmap.PortScanner()
        nm.scan(hosts=self.targets, ports=self.ports, arguments=self.nmap_arguments)
        ip_info_list = []
        for host in nm.all_hosts():
            port_info_list = []
            for proto in nm[host].all_protocols():
                port_len = len(nm[host][proto])

                for port in nm[host][proto]:
                    # 对于开了很多端口的直接丢弃
                    if port_len > 600 and (port not in [80, 443]):
                        continue

                    port_info = nm[host][proto][port]
                    item = {
                        'port_id': port,
                        'service_name': port_info['name'],
                        'version': port_info['version'],
                        'product': port_info['product'],
                        'protocol': proto
                    }

                    port_info_list.append(item)

            osmatch_list = nm[host].get('osmatch', [])
            os_info = self.os_match_by_accuracy(osmatch_list)

            ip_info = {
                'ip': host,
                'port_info': port_info_list,
                'os_info': os_info
            }
            ip_info_list.append(ip_info)

        return ip_info_list

    @staticmethod
    def os_match_by_accuracy(os_match_list):
        for os_match in os_match_list:
            accuracy = os_match.get('accuracy', '0')
            if int(accuracy) > 90:
                return os_match

        return {}


def run(targets, ports=TOP_10, service_detect=False, os_detect=False, port_parallelism=32, port_min_rate=64,
        custom_host_timeout=None):
    """
    类统一调用入口
    """
    targets = list(set(targets))
    targets = list(filter(not_in_black_ips, targets))
    if targets:
        ps = NmapScan(targets=targets, ports=ports, service_detect=service_detect, os_detect=os_detect,
                      port_parallelism=port_parallelism, port_min_rate=port_min_rate,
                      custom_host_timeout=custom_host_timeout)
        return ps.run()


if __name__ == '__main__':
    res = run(['127.0.0.1'], '80, 443, 22, 3335')
    print(res)

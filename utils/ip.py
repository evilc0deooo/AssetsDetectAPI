# -*- coding: utf-8 -*-

import ipaddress
import re
import geoip2.database
from IPy import IP
from common.baseinfo import BaseInfo
from config import BLACK_IPS, GEOIP_ASN, GEOIP_CITY
from common.log_msg import logger


class IPInfo(BaseInfo):
    def __init__(self, ip, port_info, os_info, domain, cdn_name):
        self.ip = ip
        self.port_info_list = port_info
        self.os_info = os_info
        self.domain = domain
        self._geo_asn = None
        self._geo_city = None
        self._ip_type = None
        self.cdn_name = cdn_name

    @property
    def geo_asn(self):
        if self._geo_asn:
            return self._geo_asn

        else:
            if self.ip_type == 'PUBLIC':
                self._geo_asn = get_ip_asn(self.ip)
            else:
                self._geo_asn = {}

        return self._geo_asn

    @property
    def geo_city(self):
        if self._geo_city:
            return self._geo_city

        else:
            if self.ip_type == 'PUBLIC':
                self._geo_city = get_ip_city(self.ip)
            else:
                self._geo_city = {}

        return self._geo_city

    @property
    def ip_type(self):
        if self._ip_type:
            return self._ip_type

        else:
            self._ip_type = get_ip_type(self.ip)

        return self._ip_type

    def __eq__(self, other):
        if isinstance(other, IPInfo):
            if self.ip == other.ip:
                return True

    def __hash__(self):
        return hash(self.ip)

    def _dump_json(self):
        port_info = []
        for x in self.port_info_list:
            port_info.append(x.dump_json(flag=False))

        item = {
            'ip': self.ip,
            'domain': self.domain,
            'port_info': port_info,
            'os_info': self.os_info,
            'ip_type': self.ip_type,
            'geo_asn': self.geo_asn,
            'geo_city': self.geo_city,
            'cdn_name': self.cdn_name
        }
        return item


class PortInfo(BaseInfo):
    def __init__(self, port_id, service_name='', version='', protocol='tcp', product=''):
        self.port_id = port_id
        self.service_name = service_name
        self.version = version
        self.protocol = protocol
        self.product = product

    def __eq__(self, other):
        if isinstance(other, PortInfo):
            if self.port_id == other.port_id:
                return True

    def __hash__(self):
        return hash(self.port_id)

    def _dump_json(self):
        item = {
            'port_id': self.port_id,
            'service_name': self.service_name,
            'version': self.version,
            'protocol': self.protocol,
            'product': self.product
        }
        return item


def is_vaild_ip_target(ip):
    """
    验证是否为正确 IP address
    """
    if re.match(r'^\d+\.\d+\.\d+\.\d+$|^\d+\.\d+\.\d+\.\d+/\d+$|^\d+\.\d+\.\d+.\d+-\d+$', ip):
        return True
    else:
        return False


def transfer_ip_scope(target):
    """
    将目标 IP,IP 段转换为合法的 CIDR 表示方法
    """
    try:
        return IP(target, make_net=True).strNormal(1)
    except Exception as e:
        logger.warning(f'error on ip_scope {target} {e}')


def not_in_black_ips(target):
    """
    判断目标 IP 地址是否在黑名单内
    """
    try:
        target_network = ipaddress.ip_network(target, strict=False)
    except Exception as e:
        logger.warning(f'error on check ip adder {target} {e}')
        return False
    for black_ip in BLACK_IPS:
        black_network = ipaddress.ip_network(black_ip, strict=False)
        if target_network.overlaps(black_network):
            return False

    return True


def get_ip_asn(ip):
    item = {}
    try:
        reader = geoip2.database.Reader(GEOIP_ASN)
        response = reader.asn(ip)
        item['number'] = response.autonomous_system_number
        item['organization'] = response.autonomous_system_organization
        reader.close()
    except Exception as e:
        logger.warning(f'{e} {ip}')

    return item


def get_ip_city(ip):
    """
    获取 ip 城市
    """
    try:
        reader = geoip2.database.Reader(GEOIP_CITY)
        response = reader.city(ip)
        item = {
            'city': response.city.name,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude,
            'country_name': response.country.name,
            'country_code': response.country.iso_code,
            'region_name': response.subdivisions.most_specific.name,
            'region_code': response.subdivisions.most_specific.iso_code,
        }
        reader.close()
        return item

    except Exception as e:
        logger.warning(f'{e} {ip}')
        return {}


def get_ip_type(ip):
    try:
        # 国内好多企业把这两个段当成内网域名
        if ip.startswith('9.') or ip.startswith('11.'):
            return 'PRIVATE'

        ip_type = IP(ip).iptype()

        # 为了方便全部设置为 PRIVATE
        if ip_type in ['CARRIER_GRADE_NAT', 'LOOPBACK', 'RESERVED']:
            return 'PRIVATE'

        return ip_type

    except Exception as e:
        logger.warning(f'{e} {ip}')
        return 'ERROR'


def ip_in_scope(ip, scope_list):
    for item in scope_list:
        try:
            if IP(ip) in IP(item):
                return True
        except Exception as e:
            logger.warning(f'{e} {ip} {item}')

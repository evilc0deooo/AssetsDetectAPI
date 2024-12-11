# -*- coding: utf-8 -*-

from common.base_thread import BaseThread
from utils.domain import get_ip, DomainInfo


class ResolverDomain(BaseThread):
    def __init__(self, domains, concurrency=6):
        super().__init__(domains, concurrency=concurrency)
        self.resolver_map = {}

    def work(self, domain):
        curr_domain = domain
        if isinstance(domain, dict):
            curr_domain = domain.get('domain')

        elif isinstance(domain, DomainInfo):
            curr_domain = domain.domain

        if not curr_domain:
            return

        if curr_domain in self.resolver_map:
            return

        self.resolver_map[curr_domain] = get_ip(curr_domain)

    def run(self):
        """
        解析域名
        """
        self._run()
        return self.resolver_map


def run(domains, concurrency=15):
    """
    类统一调用入口
    """
    r = ResolverDomain(domains, concurrency)
    return r.run()

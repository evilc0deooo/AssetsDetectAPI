# -*- coding: utf-8 -*-

class SiteAutoTag:
    ENTRY = '入口站点'
    MANAGE = '后台页面'
    INVALID = '无效页面'


class AutoTag(object):
    def __init__(self, site_info):
        self.site_info = site_info
        self.status = self.site_info.get('status', 0)
        self.title = self.site_info.get('title', '')
        self.headers = self.site_info.get('headers', '')

    def run(self):
        body_length = self.site_info.get('body_length', 0)

        # 通过标题判断后台登录标签
        if self.is_manage_title():
            return self._set_manage_tag()

        # 通过标题打无效标签
        if self.is_invalid_title():
            return self._set_invalid_tag()

        if not self.title and '/html' in self.headers:
            if body_length >= 200 and self.status == 200:
                self._set_entry_tag()
                return

        if body_length <= 300:
            if not self.is_redirected() and not self.title:
                self._set_invalid_tag()
                return

        if body_length <= 1000:
            if self.is_40x() or self.is_50x():
                self._set_invalid_tag()
                return

        # 通过重定向来判断页面标签
        if self.is_redirected():
            if not self.is_out():
                self._set_invalid_tag()
                return

            if 'Location: https://url.cn/sorry' in self.headers:
                self._set_invalid_tag()
                return

            header_split = self.headers.split('\n')
            manage_route_list = ['Location: /system/login', 'Location: /admin']
            manage_route_list.extend(['Location: /manage'])
            for line in header_split:
                if 'Location:' in line:
                    # 通过重定向地址判断是否为后台页面
                    for route in manage_route_list:
                        if route in line:
                            return self._set_manage_tag()

                    hostname = self.site_info.get('hostname')
                    if hostname and hostname in line:
                        return self._set_invalid_tag()
                    else:
                        return self._set_entry_tag()

            return self._set_invalid_tag()

        self._set_entry_tag()

    def is_redirected(self):
        if self.status in [301, 302, 303]:
            return True
        else:
            return False

    def is_40x(self):
        if self.status in [401, 403, 404]:
            return True
        else:
            return False

    def is_50x(self):
        if self.status in [500, 501, 502, 503, 504]:
            return True
        else:
            return False

    def _set_entry_tag(self):
        """
        打标签为入口
        """
        self.site_info['tag'] = [SiteAutoTag.ENTRY]

    def _set_invalid_tag(self):
        """
        打标签为无效
        """
        self.site_info['tag'] = [SiteAutoTag.INVALID]

    def _set_manage_tag(self):
        """
        打标签为后台
        """
        self.site_info['tag'] = [SiteAutoTag.MANAGE]

    def is_invalid_title(self):
        """
        判断是否是默认无效标题
        """
        invalid_title = ['Welcome to nginx', 'IIS7', 'Apache Tomcat']
        invalid_title.extend(['Welcome to CentOS', 'Apache HTTP Server Test Page'])
        invalid_title.extend(['Test Page for the Nginx HTTP'])
        invalid_title.extend(['500 Internal Server Error'])
        invalid_title.extend(['Error 404--Not Found'])
        invalid_title.extend(['Welcome to OpenResty'])
        invalid_title.extend(['没有找到站点', '404 not found'])
        invalid_title.extend(['页面不存在', '访问拦截', '403 Forbidden'])
        invalid_title.extend(['Page Not Found'])

        for t in invalid_title:
            if t in self.title:
                return True

        return False

    def is_manage_title(self):
        """
        判断是否是后台管理标题
        """
        manage_title = ['admin', 'Admin', 'Admin Login', 'SYSTEM', 'system', 'Platform', 'platform']
        manage_title.extend(['Administration', 'Administrator', 'Management', 'Manager', 'manager'])
        manage_title.extend(['后台登录', '运营后台', '后台管理', '正式服后台', '测试后台', '管理员登录'])
        manage_title.extend(['管理系统', '审核系统', '系统登录', '管理后台', '后台登陆', '管理平台'])
        manage_title.extend(['phpMyAdmin', 'Login to Usermin', 'Account Login', 'Well Come To Login'])

        for t in manage_title:
            if t in self.title:
                return True

        return False

    def is_out(self):
        out = ['Location: https://', 'Location: http://', 'Location: //', 'Location: /']
        for o in out:
            if o in self.headers:
                return True

        return False


def run(site_info):
    """
    类统一调用入口
    """
    if isinstance(site_info, list):
        for info in site_info:
            a = AutoTag(info)
            a.run()
        return site_info

    if isinstance(site_info, dict):
        a = AutoTag(site_info)
        a.run()
        return site_info

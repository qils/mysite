#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
import socket
import urllib
import shlex
from install.install import color_print
from mysite.api import get_mac_address
from django.core.management import execute_from_command_line
from juser.user_api import get_object, User, db_add_user

'''
直接设置环境变量将程序所在家目录加入到python模块查找路径,
'''
jms_dir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
socket.setdefaulttimeout(2)


class SetUp(object):
	def __init__(self):
		self.admin_user = 'admin'		# 默认admin管理后台, 管理员账户
		self.admin_pass = '5Lov@wife'		# 默认admin 管理后台, 管理员登录密码

	@staticmethod
	def _pull():
		'''
		检查jumpserver是否有新版本
		'''
		color_print('开始更新jumpserver', color='green')
		try:
			mac = get_mac_address()
			version = urllib.urlopen('http://jumpserver.org/version/?id=%s' % (mac, ))
		except Exception, e:
			pass

	@staticmethod
	def _sync_db():
		'''
		创建所有jumpserver使用到的数据库表
		'''
		os.chdir(jms_dir)
		execute_from_command_line(['manage.py', 'syncdb', '--noinput'])		# --noinput 参数, django不会出现输入提示

	def _input_admin(self):
		'''
		定义admin站点管理, 管理员用户名, 密码
		'''
		while True:
			admin_user = raw_input('请输入管理员用户名 [%s]: ' % (self.admin_user, )).strip()
			admin_pass = raw_input('请输入管理员密码 [%s]: ' % (self.admin_pass, )).strip()
			admin_pass_again = raw_input('请再次输入管理员密码: [%s]: ' % (self.admin_pass, )).strip()

			if admin_pass != admin_pass_again:
				color_print('两次输入的密码不一致, 请再重新输入!', color='red')
				continue
			else:
				if admin_user:
					self.admin_user = admin_user
				if admin_pass:
					self.admin_pass = admin_pass
				break

	def _create_admin(self):
		'''
		创建admin管理账号
		'''
		user = get_object(User, username=self.admin_user)		# 判断User表里面是否已存在该账号, 存在则删除记录后在创建
		if user:
			user.delete()
		db_add_user(username=self.admin_user, password=self.admin_pass, role='SU', name='admin', groups='', admin_groups='', email='admin@jumpserver.ort', uuid='MayBeYouAreTheFirstUser', is_ative=True)
		cmd = 'id %s 2>/dev/null 1>/dev/null || useradd %s' % (self.admin_user, self.admin_pass)		# 在设备上创建一个用户
		shlex.os.system(cmd)

	def start(self):
		print '开始安装JumpServer ......'
		self._pull()
		self._sync_db()
		self._input_admin()
		self._create_admin()

if __name__ == '__main__':
	setup = SetUp()
	setup.start()

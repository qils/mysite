#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from mysite.api import *
from ansible.inventory.group import Group
from ansible.inventory.host import Host
from ansible.runner import Runner
from ansible.inventory import Inventory
from passlib.hash import sha512_crypt
from django.template.loader import get_template
from django.template import Context


class MyInventory(Inventory):
	def __init__(self, resource):
		self.resource = resource
		self.inventory = Inventory(host_list=[])
		self.gen_inventory()

	def my_add_group(self, hosts, groupname, groupvars=None):
		my_group = Group(name=groupname)
		if groupvars:
			for key, value in groupvars.iteritems():
				my_group.set_variable(key, value)

		for host in hosts:
			hostname = host.get('hostname', '')		# 每个资产的主机名
			hostip = host.get('ip', '')		# 每个资产的IP地址
			hostport = host.get('port')		# 每个资产的连接端口号
			username = host.get('username', '')		# 每个资产的系统管理账号
			password = host.get('password', '')		# 每个资产的系统管理账号密码
			ssh_key = host.get('ssh_key', '')		# 每个资产的私钥
			my_host = Host(name=hostname, port=hostport)
			my_host.set_variable('ansible_ssh_host', hostip)
			my_host.set_variable('ansible_ssh_port', hostport)
			my_host.set_variable('ansible_ssh_user', username)
			my_host.set_variable('ansible_ssh_pass', password)
			my_host.set_variable('ansible_ssh_private_key_file', ssh_key)

			# 设置其他的变量
			for key, value in host.iteritems():
				if key not in ['hostname', 'port', 'username', 'password']:
					my_host.set_variable(key, value)
			my_group.add_host(my_host)
		self.inventory.add_group(my_group)

	def gen_inventory(self):
		if isinstance(self.resource, list):
			self.my_add_group(self.resource, 'default_group')
		elif isinstance(self.resource, dict):
			pass


class MyRunner(MyInventory):
	def __init__(self, *args, **kwargs):
		super(MyRunner, self).__init__(*args, **kwargs)
		self.results_raw = {}		# 保存运行结果

	def run(self, module_name='shell', module_args='', timeout=10, forks=10, pattern='*',
			become=False, become_method='sudo', become_user='root', become_pass='', transport='paramiko'):
		hoc = Runner(
			module_name=module_name,
			module_args=module_args,
			timeout=timeout,
			inventory=self.inventory,
			pattern=pattern,
			forks=forks,
			become=become,
			become_method=become_method,
			become_user=become_user,
			become_pass=become_pass,
			transport=transport
		)
		self.results_raw = hoc.run()		# 返回结果为一个字典
		logger.debug(self.results_raw)
		return self.results_raw

	@property
	def results(self):
		result = {'failed': {}, 'ok': {}}
		dark = self.results_raw.get('dark')
		contacted = self.results_raw.get('contacted')

		if dark:
			for host, info in dark.items():
				result['failed'][host] = info.get('msg')

		if contacted:
			for host, info in contacted.items():
				if info.get('invocation').get('module_name') in ['raw', 'shell', 'command', 'script']:
					if info.get('rc') == 0:
						result['ok'][host] = info.get('stdout') + info.get('stderr')
					else:
						result['failed'][host] = info.get('stdout') + info.get('stderr')
				else:
					if info.get('failed'):
						result['failed'][host] = info.get('msg')
					else:
						result['ok'][host] = info.get('changed')
		return result


class MyTask(MyRunner):
	def __init__(self, *args, **kwargs):
		super(MyTask, self).__init__(*args, **kwargs)

	@staticmethod
	def gen_sudo_script(role_list, sudo_list):
		sudo_alias = {}
		sudo_user = {}
		for sudo in sudo_list:
			sudo_alias[sudo.name] = sudo.commands

		for role in role_list:
			sudo_user[role.name] = ','.join(sudo_alias.keys())

	def add_user(self, username, password=''):
		if password:
			encrypt_pass = sha512_crypt.encrypt(password)
			module_args = 'name=%s shell=/bin/bash password=%s' % (username, encrypt_pass)
		else:
			module_args = 'name=%s shell=/bin/bash' % (username, )

		self.run('user', module_args, become=True)

		return self.results

	def push_key(self, user, key_path):
		module_args = 'user="%s" key="{{ lookup("file", "%s") }}" state=present' % (user, key_path)
		self.run('authorized_key', module_args, become=True)

		return self.results

	def push_sudo_file(self, role_list, sudo_list):
		module_args = self.gen_sudo_script(role_list, sudo_list)
		self.run('script', module_args, become=True)
		return self.results
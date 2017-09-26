#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from mysite.api import *
from tempfile import NamedTemporaryFile
from ansible.inventory.group import Group
from ansible.inventory.host import Host
from ansible.runner import Runner
from ansible.inventory import Inventory
from passlib.hash import sha512_crypt
from django.template.loader import get_template
from django.template import Context


class MyInventory(Inventory):
	def __init__(self, resource):
		self.resource = resource		# 保存所有资产信息
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
			ssh_key = host.get('ssh_key', '')		# 每个资产的私钥文件
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

	@property		# 将results变成一个属性, 通过self.results调用
	def results(self):
		result = {'failed': {}, 'ok': {}}		# 统计推送失败的资产信息, 保存信息的方式为key: 资产名称, value: 失败信息
		dark = self.results_raw.get('dark')		# 推送失败信息
		contacted = self.results_raw.get('contacted')		# 推送成功信息

		if dark:
			for host, info in dark.iteritems():
				result['failed'][host] = info.get('msg')		# 存储执行失败信息

		if contacted:
			for host, info in contacted.iteritems():
				if info.get('invocation').get('module_name') in ['raw', 'shell', 'command', 'script']:
					if info.get('rc') == 0:		# 值为0表示成功
						result['ok'][host] = info.get('stdout') + info.get('stderr')		# 保存标准错误输出, 标准输出
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
			sudo_alias[sudo.name] = sudo.commands		# sudo别名关联的系统命令	{'MM': '/bin/cp, ALL, /bin/rm'}

		for role in role_list:
			sudo_user[role.name] = ','.join(sudo_alias.keys())		# 系统用户关联的sudo别名 {'mm3': 'MM, SS'}

		sudo_j2 = get_template('jperm/role_sudo.j2')		# 加载模板,生成模板对象, role_sudo.j2是一个shell脚本, 用来修改/etc/sudoers内容
		sudo_content = sudo_j2.render(Context({'sudo_alias': sudo_alias, 'sudo_user': sudo_user}))		# 渲染模板
		sudo_file = NamedTemporaryFile(delete=False)		# 创建一个临时文件对象, delete=False指定文件保存时不删除文件
		sudo_file.write(sudo_content)
		sudo_file.close()
		return sudo_file.name		# 返回文件名

	def add_user(self, username, password=''):
		'''
		推送系统用户到目标资产, 不包括系统用户密码, 源码里面解释的是因为安全问题不在推送密码
		'''
		if password:
			encrypt_pass = sha512_crypt.encrypt(password)
			module_args = 'name=%s shell=/bin/bash password=%s' % (username, encrypt_pass)
		else:
			module_args = 'name=%s shell=/bin/bash' % (username, )

		self.run('user', module_args, become=True)

		return self.results

	def push_key(self, user, key_path):
		'''
		推送公钥到目标资产, key_path为系统用户公钥所在路径
		'''
		module_args = 'user="%s" key="{{ lookup("file", "%s") }}" state=present' % (user, key_path)
		self.run('authorized_key', module_args, become=True)

		return self.results

	def push_sudo_file(self, role_list, sudo_list):
		'''
		推送脚本, 修改系统用户权限
		'''
		module_args = self.gen_sudo_script(role_list, sudo_list)
		self.run('script', module_args, become=True)
		return self.results

	def del_user(self, username):
		'''
		删除资产上的系统用户
		'''
		if username == 'root':
			return {'status': 'failed', 'msg': 'root can not be delete'}
		module_args = 'name=%s state=absent remove=yes move_home=yes force=yes' % (username, )
		self.run('user', module_args, become=True)
		return self.results

	def del_user_sudo(self, username):
		'''
		删除系统用户sudo
		'''
		if username == 'root':
			return {'status': 'failed', 'msg': 'root can not be delete'}
		module_args = "sed -i 's/^%s.*//' /etc/sudoers" % (username, )
		self.run('command', module_args, become=True)
		return self.results

	def recycle_cmd_alias(self, role_name):
		if role_name == 'root':
			return {'status': 'failed', 'msg': u'不能回收root权限'}
		module_args = "sed -i 's/^%s.*//' /etc/sudoers" % (role_name, )
		self.run('command', module_args, become=True)
		return self.results
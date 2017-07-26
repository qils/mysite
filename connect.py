#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
import re
import pyte
import datetime
import socket
import paramiko

from mysite.api import *
from django.contrib.sessions.models import Session
from jperm.perm_api import user_have_perm


class Tty(object):
	'''
	A virtual tty class,
	虚拟终端类, 实现ssh连接和记录日志, 基类
	'''
	def __init__(self, user, asset, role, login_type='ssh'):
		self.username = user.username
		self.asset_name = asset.hostname
		self.ip = None
		self.port = 22
		self.ssh = None		# 连接成功后的ssh对象
		self.channel = None
		self.asset = asset		# 资产对象
		self.user = user
		self.role = role		# 系统用户对象
		self.remote_ip = ''		# 获取客户端IP
		self.login_type = login_type		# 登录类型, 通过web登录, 或者ssh登录
		self.vim_flag = False
		self.vim_end_pattern = re.compile(r'\x1b\[\?1049', re.X)
		self.vim_data = ''
		self.stream = None		# 初始化字符流
		self.screen = None		# 初始化屏幕
		self.__init_screen_stream()

	def __init_screen_stream(self):
		'''
		初始化虚拟屏幕和字符流
		'''
		self.stream = pyte.ByteStream()
		self.screen = pyte.Screen(80, 24)
		self.stream.attach(self.screen)

	def get_log(self):
		'''
		记录用户日志
		'''
		tty_log_dir = os.path.join(settings.LOG_DIR, 'tty')		# 定义tty日志目录
		date_today = datetime.datetime.now()
		date_start = date_today.strftime('%Y%m%d')
		time_start = date_today.strftime('%H%M%S')
		today_connect_log_dir = os.path.join(tty_log_dir, date_start)		# 定义当天连接请求的日志目录
		log_file_path = os.path.join(today_connect_log_dir, '%s_%s_%s' % (self.username, self.asset_name, time_start))

		try:
			mkdir(tty_log_dir, mode=777)
			mkdir(today_connect_log_dir, mode=777)
		except OSError:
			logger.debug(u'创建目录 %s 失败, 请修改 %s 目录权限' % (today_connect_log_dir, tty_log_dir))
			raise ServerError(u'创建目录 %s 失败, 请修改 %s 目录权限' % (today_connect_log_dir, tty_log_dir))

		try:
			log_file_f = open(log_file_path + '.log', 'a')
			log_time_f = open(log_file_path + '.time', 'a')
		except IOError:
			logger.debug(u'创建tty日志文件失败, 请修改目录 %s 权限' % (today_connect_log_dir, ))
			raise ServerError(u'创建tty日志文件失败, 请修改目录 %s 权限' % (today_connect_log_dir, ))

		if self.login_type == 'ssh':		# ssh 连接过来, 记录为connect.py的pid, web terminal终端连接记录为日志的id
			pid = os.getpid()
			# self.remote_ip = remote_ip
		else:
			pid = 0

		log = Log(
			user=self.username,
			host=self.asset_name,
			remote_ip=self.remote_ip,
			login_type=self.login_type,
			log_path=log_file_path,
			start_time=date_today,
			pid=pid
		)
		log.save()		# 将数据写入到jlog.models.Log 模型中
		if self.login_type == 'web':
			log.pid = log.id
			log.save()
		log_file_f.write('Start at %s \r\n' % (datetime.datetime.now()))
		return log_file_f, log_time_f, log

	def get_connect_info(self):
		'''
		获取需要登录的主机信息以及映射用户的账号密码
		'''
		asset_info = get_asset_info(self.asset)		# 获取指定一个资产信息, 信息保存在字典对象中
		role_key = get_role_key(self.user, self.role)		# 获取系统用户私钥路径信息, 需要将文件权限设置为0600
		role_pass = CRYPTOR.decrypt(self.role.password)		# 获取系统映射的密码, 目前该密码不再被推送到资产
		connect_info = {
			'user': self.user,		# User 对象
			'asset': self.asset,		# 资产对象
			'ip': asset_info.get('ip'),		# 连接资产IP
			'port': int(asset_info.get('port')),		# 连接资产端口号
			'role_name': self.role.name,		# 登录资产使用的系统用户
			'role_pass': role_pass,		# 系统用户映射的密码
			'role_key': role_key		# 系统用户映射的私钥路径
		}
		logger.debug(connect_info)		# 记录连接信息
		return connect_info

	def get_connection(self):
		'''
		获取连接成功后的ssh
		'''
		connect_info = self.get_connect_info()

		ssh = paramiko.SSHClient()		# 发起ssh连接请求
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())		# 允许连接不在know_hosts文件中的主机
		try:
			role_key = connect_info.get('role_key')
			if role_key and os.path.isfile(role_key):
				try:
					ssh.connect(
						connect_info.get('ip'),
						port=connect_info.get('port'),
						username=connect_info.get('role_name'),
						password=connect_info.get('role_pass'),
						key_filename=role_key,		# 通过密钥验证连接目标主机
						look_for_keys=False
					)
					return ssh
				except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException):
					logger.warning(u'使用ssh key %s 失败, 尝试只使用密码' % (role_key, ))
					pass

			ssh.connect(
				connect_info.get('ip'),
				port=connect_info.get('port'),
				username=connect_info.get('role_name'),
				password=connect_info.get('role_pass'),
				allow_agent=False,
				look_for_keys=False
			)
		except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException):
			raise ServerError(u'认证失败')
		except socket.error:
			raise ServerError(u'端口号可能不对')
		else:
			self.ssh = ssh
			return ssh

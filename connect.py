#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
import sys
import re
import errno
import textwrap
import pyte
import datetime
import socket
import paramiko
import operator
import getpass
import django
import struct, fcntl, signal, select

from install.setup import color_print
from mysite.api import *
from django.contrib.sessions.models import Session
from jperm.perm_api import user_have_perm, get_group_user_perm, gen_resource
from jperm.ansible_api import MyRunner

os.environ['DJANGO_SETTINGS_MODULE'] = 'mysite.settings'
if not django.get_version().startswith('1.6'):
	setup = django.setup()

from jlog.views import TermLogRecorder

login_user = get_object(User, username=getpass.getuser())		# 登录堡垒机账号名称
try:
	remote_ip = os.environ.get('SSH_CLIENT', '').split()[0]		# 获取远程登录堡垒机的来源IP地址
except (IndexError, AttributeError):
	remote_ip = os.popen("who -m | awk '{print $NF}'").read().strip('(\n)')

try:
	import termios
	import tty
except ImportError:
	color_print(u'仅支持类Unix系统')
	time.sleep(3)
	sys.exit()


class Tty(object):
	'''
	A virtual tty class,
	虚拟终端类, 实现ssh连接和记录日志, 基类
	'''
	def __init__(self, user, asset, role, login_type='ssh'):
		self.username = user.username
		self.asset_name = asset.hostname		# 登录资产名称
		self.ip = None
		self.port = 22
		self.ssh = None		# 连接成功后的ssh对象
		self.channel = None
		self.asset = asset		# 资产对象
		self.user = user		# User授权用户对象
		self.role = role		# 系统用户对象
		self.remote_ip = ''		# 保存登录的远程客户端IP(从哪个客户端IP登录到跳板机)
		self.login_type = login_type		# 登录类型, 通过web登录, 或者ssh登录
		self.vim_flag = False
		self.vim_begin_pattern = re.compile(r'\x1b\[\?1049h', re.X)		# vim 开始, 源码反馈说有性能问题, 现在改用这种方式
		self.vim_end_pattern = re.compile(r'\x1b\[\?1049l', re.X)		# vim 结束
		# self.vim_end_pattern = re.compile(r'\x1b\[\?1049', re.X)
		# self.vim_data = ''
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

	@staticmethod
	def is_output(string):
		newline_char = ['\n', '\r', '\r\n']
		for char in newline_char:
			if char in string:
				return True
		return False

	@staticmethod
	def command_parser(command):
		result = None
		match = re.compile('\[?.*@.*\]?[\$#]\s').split(command)		# 依据终端提示符分割, 取最后的索引能获得输入的命令
		if match:
			result = match[-1].strip()
		else:
			match = re.split('mysql>\s', command)
			if match:
				result = match[-1].strip()
		return result

	def deal_command(self, data):
		'''
		处理截获的命令, 主要是处理Tab键补齐时，从返回的数据中提取输入的命令字符
		'''
		command = ''
		try:
			self.stream.feed(data)
			for line in reversed(self.screen.buffer):
				line_data = ''.join(map(operator.attrgetter('data'), line)).strip()		# operator获取对象的属性
				if len(line_data) > 0:
					parser_result = self.command_parser(line_data)
					if parser_result is not None:
						if len(parser_result) > 0:
							command = parser_result
					else:
						command = line_data
					break
		except Exception:
			pass
		self.screen.reset()
		return command

	def get_log(self):
		'''
		记录用户日志到 jlog.models.Log 模型
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
			self.remote_ip = remote_ip		# 保存客户端IP
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

		ssh = paramiko.SSHClient()		# 建立一个sshclient对象
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())		# 允许连接不在know_hosts文件中的主机
		try:
			role_key = connect_info.get('role_key')		# 获取系统用户的私钥文件路径
			if role_key and os.path.isfile(role_key):
				try:
					ssh.connect(		# 调用connect方法连接目标服务器
						connect_info.get('ip'),		# 连接IP
						port=connect_info.get('port'),		# 连接端口号
						username=connect_info.get('role_name'),		# 系统用户名
						password=connect_info.get('role_pass'),		# 系统用户密码
						key_filename=role_key,		# 通过私钥验证连接目标主机, 可用使用timeout设置连接超时时间
						look_for_keys=False		# 是否允许搜索私钥文件
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
				allow_agent=False,		# 是否允许使用ssh代理
				look_for_keys=False
			)
		except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException):
			raise ServerError(u'认证失败')
		except socket.error:
			raise ServerError(u'端口号可能不对')
		else:
			self.ssh = ssh
			return ssh


class SshTty(Tty):
	'''
	一个虚拟终端类, 实现ssh连接和记录日志
	'''
	@staticmethod
	def get_win_size():
		'''
		获取terminal窗口大小
		'''
		if 'TIOCGWINSZ' in dir(termios):
			TIOCGWINSZ = termios.TIOCGWINSZ
		else:
			TIOCGWINSZ = 1074295912L
		s = struct.pack('4H', 0, 0, 0, 0)
		x = fcntl.ioctl(sys.stdout.fileno(), TIOCGWINSZ, s)
		return struct.unpack('4H', x)[0:2]

	@staticmethod
	def set_win_size():
		'''
		设置terminal 窗口大小, 在捕获SIGWINCH窗口大小变化时调用
		'''
		try:
			win_size = self.get_win_size()
			self.channel.resize_pty(height=win_size[0], width=win_size[1])
		except Exception:
			pass

	def posix_shell(self):
		'''
		使用paramiko模块的channel(通道), 连接后端, 进入交互式
		'''
		log_file_f, log_time_f, log = self.get_log()
		termlog = TermLogRecorder(User.objects.get(id=self.user.id))		# 创建一个TermLogRecorder实例
		termlog.setid(log.id)
		old_tty = termios.tcgetattr(sys.stdin)		# 获取原操作终端属性
		pre_timestamp = time.time()
		data = ''
		input_mode = False

		try:
			tty.setraw(sys.stdin.fileno())		# 将当前操作终端属性设置为服务器原操作终端属性
			tty.setcbreak(sys.stdin.fileno())
			self.channel.settimeout(0.0)

			while True:
				try:
					r, w, e = select.select([self.channel, sys.stdin], [], [])		# select对输入终端和channel进行监控
					flag = fcntl.fcntl(sys.stdin, fcntl.F_GETFL, 0)
					fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, flag|os.O_NONBLOCK)
				except Exception:
					pass

				if self.channel in r:		# 远程服务器返回执行命令结果, channel通道接受到结果发生变化, select感知到变化
					try:
						x = self.channel.recv(10240)		# 从通道读取服务器返回的数据, 第一次连接上服务器会返回两次数据
						if len(x) == 0:
							break

						index = 0
						len_x = len(x)
						while index < len_x:
							try:
								n = os.write(sys.stdout.fileno(), x[index:])		# 将结果输出到终端
								sys.stdout.flush()
								index += n
							except OSError as msg:
								if msg.errno == errno.EAGAIN:
									continue

						now_timestamp = time.time()
						termlog.write(x)
						termlog.recoder = False
						log_time_f.write('%s %s\n' % (round(now_timestamp - pre_timestamp, 4), len(x)))		# 纪录时间差和返回字符长度
						log_time_f.flush()
						log_file_f.write(x)		# 将返回结果写入文件
						log_file_f.flush()
						pre_timestamp = now_timestamp		# 重置时间

						# self.vim_data += x		# 将返回值保存在self.vim_data中, 当输入回车后, 重置为空, 保存执行命令后的结果字符
						if self.vim_begin_pattern.findall(x):
							self.vim_flag = True
						elif self.vim_end_pattern.findall(x):
							self.vim_flag = False

						if input_mode:		# 判断是否是输入模式, 如果是则保存输入字符命令
							data += x
					except socket.timeout:
						pass

				if sys.stdin in r:		# 终端输入命令, sys.stdin发生变化, select感知到变化
					try:
						x = os.read(sys.stdin.fileno(), 4096)		# 获取终端输入的内容
					except OSError:
						pass

					termlog.recoder = True
					input_mode = True
					if self.is_output(str(x)):		# 检查终端输入字符是否为 \n, \r, \rn 这三种字符, 如果是则返回True
						if len(str(x)) > 1:		# 表示复制内容到终端
							data = x

						if not self.vim_flag:
							self.vim_flag = False
							data = self.deal_command(data)[0:200]		# 对data进行处理, 主要是在Tab补齐是会有很多额外的返回字符
							if data is not None:
								TtyLog(log=log, datetime=datetime.datetime.now(), cmd=data).save()

						data = ''		# 重新将输入命令设置为空
						input_mode = False		# 设置为False, 在命令返回结果时保证data不保存返回的结果字符

					if len(x) == 0:
						break
					self.channel.send(x)		# 将输入字符通过channel通道发送到远程服务器
		finally:
			termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_tty)		# 将当前操作终端属性设置为最初保存的操作终端属性
			log_file_f.write('End time is %s\n' % (datetime.datetime.now()))
			log_file_f.close()
			log_time_f.close()
			termlog.save()
			log.filename = termlog.filename
			log.is_finished = True
			log.end_time = datetime.datetime.now()
			log.save()

	def connect(self):
		'''
		连接服务器
		'''
		ssh = self.get_connection()		# 建立ssh 实列对象
		transport = ssh.get_transport()
		transport.set_keepalive(30)
		transport.use_compression(True)

		global channel
		win_size = self.get_win_size()
		self.channel = channel = transport.open_session()		# 打开一个channel(通道)
		channel.get_pty(term='xterm', height=win_size[0], width=win_size[1])		# 获取终端
		channel.invoke_shell()		# 建立交互式shell连接, 激活终端, 可以登录到终端

		try:
			signal.signal(signal.SIGWINCH, self.set_win_size)		# 设置信号处理函数, SIGWINCH为窗口大小变化信号
		except:
			pass

		self.posix_shell()

		channel.close()
		ssh.close()


class Nav(object):
	'''
	导航提示类
	'''
	def __init__(self, user):
		self.user = user
		self.user_perm = get_group_user_perm(self.user)		# 获取用户授权信息
		if settings.NAV_SORT_BY == 'ip':		# 通过资产IP来排序
			self.perm_assets = sorted(		# 返回排序后的资产列表
				self.user_perm.get('asset', []).keys(), key=lambda x: [int(num) for num in x.ip.split('.') if num.isdigit()]
			)
		elif settings.NAV_SORT_BY == 'hostname':		# 通过资产名称排序
			self.perm_assets = self.natural_sort_hostname(self.user_perm.get('asset', []).keys())
		else:
			self.perm_assets = tuple(self.user_perm.get('asset', []))

		self.search_result = self.perm_assets		# 搜索结果保存, 默认赋值为所有授权资产
		self.perm_asset_groups = self.user_perm.get('asset_group', [])		# 所有授权的资产组

	def natural_sort_hostname(self, alist):
		convert = lambda text: int(text) if text.isdigit() else text.lower()
		return sorted(alist, key=lambda x: [convert(c) for c in re.split('([0-9]+)', x.hostname)])

	def try_connect(self):
		'''
		连接远程目标主机
		'''
		try:
			asset = self.search_result[0]		# 获取登录的目标资产
			roles = list(self.user_perm.get('asset').get(asset).get('role'))		# 获取资产授权的系统用户
			if len(roles) == 1:
				role = roles[0]
			elif len(roles) > 1:
				print '\033[32m[ID] 系统用户\033[0m'
				for index, role in enumerate(roles):		# 当系统用户超过1时, 需要选择登录的系统用户
					print '[%-2s] %s' % (index, role.name)
				print

				print '授权系统用户超过1个, 请输入ID, q退出'
				try:
					role_index = raw_input('\033[1;32mID>:\033[0m ').strip().lower()
					if role_index == 'q':
						return
					else:
						role = roles[int(role_index)]
				except (IndexError, ValueError):
					color_print(u'请输入正确的ID', color='red')
					return
			else:
				color_print(u'没有授权的系统用户', color='red')
				return

			color_print(u'Connecting %s, username %s ....' % (asset.ip, role.name), color='blue')
			ssh_tty = SshTty(login_user, asset, role)		# 创建ssh_tty实列对象
			ssh_tty.connect()
		except (KeyError, ValueError):
			color_print(u'请输入正确的ID', color='red')
		except ServerError, e:
			color_print(e, color='red')

	def print_asset_group(self):
		'''
		输出用户授权的资产组信息
		'''
		color_print('[%-3s] %-20s %s' % ('ID', '资产组名', '备注'))
		for asset_group in self.perm_asset_groups:
			print '[%-3s] %-20s %s' % (asset_group.id, asset_group.name, asset_group.comment)
		print

	def exec_cmd(self):
		'''
		批量执行命令
		'''
		while True:
			roles = self.user_perm.get('role').keys()		# 获取授权的系统用户
			if len(roles) > 1:		# 当授权的系统用户大于一时需要选择用哪个系统用户登录远程主机执行命令
				color_print('[%-2s] %-15s' % ('ID', u'系统用户'), color='info')

				for i, r in enumerate(roles):
					print '[%-2s] %-15s' % (i, r.name)
				print
				print u'请输入运行命令所关联系统用户ID, q退出'

				try:
					role_id = int(raw_input('\033[1;32mRole>:\033[0m ').strip().lower())		# 增加小写转换函数
					if role_id == 'q':
						break
				except (IndexError, ValueError):
					color_print(u'输入错误', color='red')
				else:
					try:
						role = roles[role_id]		# 取索引对应的系统用户
					except IndexError:
						print u'输入索引超过授权系统用户个数'
						continue
			elif len(roles) == 1:
				role = roles[0]
			else:
				color_print(u'当前用户未被授权系统用户, 无法执行任何操作, 请联系管理员')
				return

			assets = list(self.user_perm.get('role').get(role).get('asset'))		# 获取所选系统用户授权的所有资产
			print u'授权包含该系统用户的所有主机'
			for asset in assets:
				print '%s' % (asset.hostname, )
			print

			print u'请输入主机名或ansible支持的pattern, 多个主机:分隔, q退出'
			pattern = raw_input('\033[1;32mPattern>:\033[0m ').strip()
			if pattern == 'q':
				break
			else:
				res = gen_resource({'user': self.user, 'asset': assets, 'role': role}, perm=self.user_perm)
				runner = MyRunner(res)		# 调用ansible接口, 初始化所有目标主机信息

				asset_name_str = ''		# 匹配目的主机, 批量执行时可以先对一台设备执行, 然后可以选*对所有设备执行
				print u'匹配主机: '
				for inv in runner.inventory.get_hosts(pattern=pattern):
					print '%s' % (inv.name, )
					asset_name_str += ' %s' % (inv.name, )
				print

				while True:
					print u'请输入执行的命令: 按q退出'
					command = raw_input('\033[1;32mCmds>:\033[0m ').strip()
					if command == 'q':
						break
					elif not command:
						color_print(u'输入命令不能为空...')
						continue
					runner.run('shell', command, pattern=pattern)
					ExecLog(host=asset_name_str.split(' ')[0:10], 		# 防止目标主机执行过多调整为只存10条主机记录
						user=self.user.username,
						cmd=command,
						remote_ip=remote_ip,
						result='success'
					).save()

					for k, v in runner.results():
						if k == 'ok':
							for host, output in v.iteritems():
								color_print('%s => %s' % (host, 'Success'), color='green')
								print output
								print
						else:
							for host, output in v.iteritems():
								color_print('%s => %s' % (host, 'Fail'), color='red')
								print output
								print
					print '~o~ Task finished ~o~'
					print

	def get_asset_group_member(self, str_r):
		'''
		依据输入g1, g2, G1, G2... 查下条件, 输出对应资产组中资产信息
		'''
		gid_pattern = re.compile(r'^g\d+$', re.I)
		if gid_pattern.match(str_r):
			gid = int(str_r.lstrip('gG'))		# 获取查询的gid
			asset_group = get_object(AssetGroup, id=gid)
			if asset_group and asset_group in self.perm_asset_groups:
				self.search_result = list(asset_group.asset_set.all())
			else:
				color_print(u'没有该资产组或没有访问该资产组权限')
				self.search_result = []		# 没有匹配的组时, 输出结果需要置为空, 否则将会打印上一次的结果

	@staticmethod
	def print_nav():
		'''
		打印提示导航
		'''
		msg = '''\n\033[1;32m###	欢迎使用Jumpserver开源跳板机系统	###\033[0m
		1) 输入 \033[32mID\033[0m 直接登录或输入\033[32m部分IP, 主机名, 备注\033[0m进行搜索登录(如果唯一).
		2) 输入 \033[32m/\033[0m + \033[32mIP, 主机名 or 备注 \033[0m搜索, 如: /ip.
		3) 输入 \033[32mP/p\033[0m显示有权限的主机.
		4) 输入 \033[32mG/g\033[0m显示有权限的主机组.
		5) 输入 \033[32mG/g\033[0m + \033[32m组ID\033[0m显示该组下的主机, 如: g1.
		6) 输入 \033[32mE/e\033[0m批量执行命令.
		7) 输入 \033[32mU/u\033[0m批量上传文件.
		8) 输入 \033[32mD/d\033[0m批量下载文件.
		9) 输入 \033[32mH/h\033[0m显示帮助.
		10) 输入 \033[32mQ/q\033[0m退出程序.
		'''
		print textwrap.dedent(msg)

	def search(self, str_r=''):
		'''
		保存搜索结果: [<Asset: ip>, ....]
		'''
		if str_r:
			try:
				id_ = int(str_r)		# 输入的是数字字符, 直接输入ID时, 过滤需要登录的主机
				if id_ < len(self.perm_assets):
					self.search_result = [self.perm_assets[id_]]		# 返回对应的索引资产, 这里和源码不同, self.search_result 会变化, 所以用self.perm_assets
					return
				else:
					raise ValueError
			except (ValueError, TypeError):
				str_r = str_r.lower()
				self.search_result = [asset for asset in self.perm_assets if str_r in str(asset.ip).lower() or str_r in str(asset.hostname).lower() or str_r in str(asset.comment).lower()]		# 搜索匹配ip, hostname, 备注的资产
		else:		# 没有搜索字符, 默认展示所有资产
			self.search_result = self.perm_assets

	@staticmethod
	def get_max_asset_property_length(assets, property_='hostname'):
		'''
		返回最大的主机名长度
		'''
		try:
			return max([len(getattr(asset, property_)) for asset in assets])
		except ValueError:
			return 30		# 默认返回长度为30

	@staticmethod
	def truncate_str(str_, length=30):
		'''
		字符串截断
		'''
		str_ = str_.decode('utf-8')
		if len(str_) > length:
			return str_[:14] + '...' + str_[-14:]
		else:
			return str_

	def print_search_result(self):
		'''
		输出搜索到的资产信息
		'''
		hostname_max_length = self.get_max_asset_property_length(self.search_result)		# 获取资产最大主机名长度
		line = '[%-5s] %-16s %-6s %-' + str(hostname_max_length) + 's %-20s %s'		# 定义输出格式
		color_print(line % ('ID', '[Ip]', '[Port]', '[Hostname]', '[SysUser(系统用户)]', '[Comment]'), 'title')
		if hasattr(self.search_result, '__iter__'):		# 当搜索结果不为空时, 迭代所有资产信息
			for index, asset in enumerate(self.search_result):
				asset_info = get_asset_info(asset)
				role = [str(role.name) for role in self.user_perm.get('asset').get(asset).get('role')]		# 获取资产上的系统用户
				try:
					print line % (index, asset.ip, asset_info.get('port'), self.truncate_str(asset.hostname), str(role).replace("'", ''), asset.comment)
				except:
					print line % (index, asset.ip, asset_info.get('port'), self.truncate_str(asset.hostname), str(role).replace("'", ''), '')
		print
					

def main():
	'''
	授权用户登录堡垒机服务器后执行的主程序函数
	'''
	if not login_user:		# 检查登录用户是否存在
		color_print(u'没有该用户, 或许你是root运行的', exits=True)

	if not login_user.is_active:		# 检查登录用户是否被激活
		color_print(u'该用户[%s]已被禁用, 请联系管理员.' % (login_user.username, ), exits=True)

	gid_pattern = re.compile(r'^g\d+$', re.I)		# 组匹配模式, g1, g2...., 源码中没有re.I, 增加G1, G2...匹配
	nav = Nav(login_user)		# 创建一个导航栏实例对象
	nav.print_nav()

	try:
		while True:
			try:
				option = raw_input('\033[1;32mOpt or ID>:\033[0m ').strip()
			except EOFError:
				break
				nav.print_nav()
				continue
			except KeyboardInterrupt:
				sys.exit(0)

			if option in ['P', 'p', '\n', '']:		# 输出用户授权的主机信息
				nav.search()
				nav.print_search_result()
				continue

			if option.startswith('/'):		# 搜索匹配以/ip 这种形式的资产
				nav.search(option.lstrip('/'))
				nav.print_search_result()
				continue
			elif gid_pattern.match(option):
				nav.get_asset_group_member(str_r=option)		# 获取某个资产组中的资产信息
				nav.print_search_result()
				continue
			elif option in ['G', 'g']:		# 打印用户授权的资产组信息
				nav.print_asset_group()
				continue
			elif option in ['H', 'h']:
				nav.print_nav()
				continue
			elif option in ['E', 'e']:
				nav.exec_cmd()
				continue
			elif option in ['Q', 'q', 'exit', 'quit']:		# 退出循环
				sys.exit()
			else:		# 主要判断是否输入的是一个ID字符数字, 通过该ID索引从self.perm_assets中取对应的一个资产
				nav.search(option)
				if len(nav.search_result) == 1:		# 匹配只有一台主机时才会进行登录连接操作
					target_asset = nav.search_result[0]
					color_print('Only match Hostname: %s Ip: %s' % (target_asset.hostname, target_asset.ip), color='blue')
					nav.try_connect()		# 开始连接远程目标主机
				else:
					nav.print_search_result()		# 搜索到的资产大于1,将打印搜索结果
	except IndexError, e:
		color_print(e)
		time.sleep(5)


if __name__ == '__main__':
	main()

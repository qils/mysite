#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import re
import sys
import time
import select
import datetime
import os.path
import functools
import tornado.options
import tornado.web
import tornado.ioloop
import threading
import tornado.httpserver
import tornado.websocket

from pyinotify import WatchManager, ProcessEvent, IN_DELETE, IN_CREATE, IN_MODIFY, AsyncNotifier

from tornado.websocket import WebSocketClosedError
from connect import logger, get_object, User, Asset, Tty, ServerError
from connect import Session, user_have_perm
from mysite.settings import IP, PORT
from install.setup import color_print
from tornado.options import options, define
from django.core.signals import request_finished, request_started
from jlog.views import TermLogRecorder

try:
	import simplejson as json
except ImportError:
	import json

# type=int表示参数类型是整型
define('port', default=PORT, help='run on the given port', type=int)		# 定义port参数, 通过options.port调用
define('host', default=IP, help='run port on given host', type=str)			# 定义host参数, 通过options.host调用


def django_request_support(func):		# func 参数为require_auth中的_deco2函数
	@functools.wraps(func)		# 该装饰器作用是将原函数指定属性复制给包装函数
	def _deco(*args, **kwargs):		# args=(self, )
		request_started.send_robust(func)
		response = func(*args, **kwargs)		# 这里调用等价于_deco2(self)		# self是tornado请求客户端实列
		request_finished.send_robust(func)
		return response

	return _deco


def require_auth(role='user'):
	def _deco(func):		# func 参数为open函数
		def _deco2(request, *args, **kwargs):
			if request.get_cookie('sessionid'):		# request等同于tornado实列self
				session_key = request.get_cookie('sessionid')		# 获取cookie, 这个cookie是django会话设置的cookie
			else:
				session_key = request.get_argument('sessionid', '')		# tornado方法获取提交的参数值
			logger.debug('WebSocket: session_key: [ %s ]' % (session_key, ))		# 记录日志
			if session_key:
				session = get_object(Session, session_key=session_key)		# 从Session 模型中过滤满足条件的session记录
				logger.debug('Websocket: session: [ %s ]' % (session, ))
				if session and datetime.datetime.now() < session.expire_date:		# 判断会话记录是否存在, 并且会话没有过期
					user_id = session.get_decoded().get('_auth_user_id')		# 获取User id
					request.user_id = user_id		# 保存User id
					user = get_object(User, id=user_id)		# 获取请求的用户身份
					if user:
						logger.debug('Websocket: user [ %s ] request websocket' % (user.username, ))		# 记录请求的用户名
						request.user = user		# 保存User对象
						if role == 'admin':
							if user.role in ['SU', 'GA']:
								return func(request, *args, **kwargs)		# 等价于执行 open(self)
							logger.debug('Websocket: user [ %s ] is not admin' % (user.username, ))
						else:
							return func(request, *args, **kwargs)
				else:
					logger.debug('Websocket: session expired: [ %s ]' % (session_key, ))		# 会话过期, 记录日志
			try:
				request.close()		# 服务器端主动断开连接
			except AttributeError:
				pass
			logger.debug('Websocket: Request auth failed!')

		return _deco2
	return _deco


class MyThread(threading.Thread):
	def __init__(self, *args, **kwargs):
		super(MyThread, self).__init__(*args, **kwargs)

	def run(self):
		try:
			super(MyThread, self).run()
		except WebSocketClosedError:
			pass


class WebTty(Tty):
	def __init__(self, *args, **kwargs):
		super(WebTty, self).__init__(*args, **kwargs)
		self.ws = None
		self.data = ''
		self.input_mode = False


class EventHandler(ProcessEvent):
	def __init__(self, client=None):
		self.client = client

	def process_IN_MODIFY(self, event):
		self.client.write_message(f.read().decode('utf-8', 'replace'))		# 将日志文件变更信息,返回给web客户端


def file_monitor(path='.', client=None):
	'''
	实时日志监控, 通过调用pyinotify模块基于inotify事件驱动机制
	'''
	wm = WatchManager()		# 创建实例
	mask = IN_DELETE | IN_CREATE | IN_MODIFY		# 定义监控事件: 文件创建, 文件删除, 文件内容变更
	notifier = AsyncNotifier(wm, EventHandler(client))		# 指定事件处理器
	wm.add_watch(path, mask, auto_add=True, rec=True)		# 添加监控事件, 对指定的path文件系统监控

	if not os.path.isfile(path):
		logger.debug(u'File %s is not exist' % (path, ))
		sys.exit(3)
	else:
		logger.debug(u'Now starting monitor file %s' % (path, ))
		global f
		with open(path, 'r') as f:
			st_size = os.stat(path)[6]
			f.seek(st_size)		# 文件指针偏转到文件末尾

	while True:
		try:
			notifier.process_events()		# 处理事件
			if notifier.check_events():
				notifier.read_events()		# 读取事件缓存
		except KeyboardInterrupt:
			notifier.stop()
			break


class MonitorHandler(tornado.websocket.WebSocketHandler):
	'''
	日志监控
	'''
	clients = []		# 定义客户端类属性, 所有实例访问结果一样
	threads = []		# 定义线程类属性

	def __init__(self, *args, **kwargs):
		self.file_path = None
		super(self.__class__, self).__init__(*args, **kwargs)

	def check_origin(self, origin):
		return True

	@django_request_support
	@require_auth('admin')
	def open(self):
		self.file_path = self.get_argument('file_path', '')		# 获取提交的参数
		MonitorHandler.clients.append(self)
		thread = MyThread(target=file_monitor, args=('%s.log' % (self.file_path, ), self))		# 创建线程
		MonitorHandler.threads.append(thread)
		self.stream.set_nodelay(True)

		try:
			for t in MonitorHandler.threads:
				if t.is_alive():
					continue
				t.setDaemon(True)
				t.start()
		except WebSocketClosedError:
			client_index = MonitorHandler.clients.index(self)
			MonitorHandler.threads[client_index].stop()		# WebSocket关闭时, 停掉进程
			MonitorHandler.clients.remove(self)
			MonitorHandler.threads.remove(MonitorHandler.threads[client_index])

		logger.debug('Websocket: Monitor client num: %s, thread num: %s' % (len(MonitorHandler.clients), len(MonitorHandler.threads)))

	def on_message(self, message):
		'''
		客户端发送消息后调用
		'''
		pass

	def on_close(self):
		'''
		客户端主动关闭
		'''
		logger.debug('Websocket: Monitor client close request')
		try:
			client_index = MonitorHandler.clients.index(self)
			MonitorHandler.clients.remove(self)
			MonitorHandler.threads.remove(MonitorHandler.threads[client_index])
		except Exception:
			pass


class WebTerminalHandler(tornado.websocket.WebSocketHandler):		# tornado websocket实现http长轮询
	clients = []		# 保存所有请求客户端
	tasks = []		# 保存所有线程对象

	def __init__(self, *args, **kwargs):
		self.term = None		# 虚拟终端对象, WebTty的一个实列
		self.log_file_f = None
		self.log_time_f = None
		self.log = None		# Log日志记录对象
		self.id = 0
		self.user = None		# 保存请求的User对象
		self.ssh = None		# 连接后的ssh对象
		self.channel = None
		super(WebTerminalHandler, self).__init__(*args, **kwargs)

	def check_origin(self, origin):
		return True

	@django_request_support
	@require_auth('user')
	def open(self):		# 连接打开时该方法被调用, self.open = django_request_support(require_auth('user')(open))(self)
		logger.debug('WebSocket: Open request')
		role_name = self.get_argument('role', 'sb')		# 获取提交的系统用户role参数值, 默认为sb, ^_^!
		asset_id = self.get_argument('id', 9999)		# 获取提交的资产id参数值
		asset = get_object(Asset, id=asset_id)		# 获取对应的资产对象
		self.termlog = TermLogRecorder(User.objects.get(id=self.user_id))
		if asset:
			roles = user_have_perm(self.user, asset)		# 获取授权用户授权资产所授权的系统用户
			logger.debug(roles)
			logger.debug(u'系统用户: %s' % (role_name, ))
			login_role = ''		# 定义登录设备的系统用户对象
			for role in roles:
				if role.name == role_name:
					login_role = role
					break
			if not login_role:		# 没有与参数中role_name相同的系统用户则服务器端主动关闭连接
				logger.warning('Websocket: Not that Role %s for host: %s User: %s' % (role_name, asset.hostname, self.user.username))
				self.close()
				return
		else:
			logger.warning('Websocket: No that Host: %s User: %s' % (asset_id, self.user.username))
			self.close()
			return
		logger.debug('Websocket: request web terminal Host: %s User: %s Role: %s' % (asset.hostname, self.user.username, login_role.name))

		self.term = WebTty(self.user, asset, login_role, login_type='web')
		self.term.remote_ip = self.request.headers.get('X-Real_IP')
		if not self.term.remote_ip:
			self.term.remote_ip = self.request.remote_ip		# 获取客户端IP
		try:
			self.ssh = self.term.get_connection()
		except ServerError:
			self.close()		# 捕获连接失败, 服务器端主动关闭连接
			return
		self.channel = self.ssh.invoke_shell(term='xterm')		# 建立交互式shell连接
		WebTerminalHandler.tasks.append(MyThread(target=self.forward_outbound))		# 创建Thread对象
		WebTerminalHandler.clients.append(self)

		for t in WebTerminalHandler.tasks:
			if t.is_alive():
				continue
			try:
				t.setDaemon(True)		# 将线程放到后台执行
				t.start()		# 启动线程
			except RuntimeError:
				pass

	def forward_outbound(self):
		self.log_file_f, self.log_time_f, self.log = self.term.get_log()
		self.id = self.log.id
		self.termlog.setid(self.id)
		try:
			data = ''
			pre_timestamp = time.time()
			while True:
				r, w, e = select.select([self.channel], [], [])
				if self.channel in r:
					recv = self.channel.recv(1024)
					if not len(recv):
						return
					data += recv
					self.term.vim_data += recv		# 保存连接的目标主机回显的所有字符, 包括执行命令的结果, 虚拟终端提示符
					try:
						self.write_message(data.decode('utf-8', 'replace'))		# 回显给web客户端
						self.termlog.write(data)
						self.termlog.recoder = False
						now_timestamp = time.time()
						self.log_time_f.write('%s %s\n' % (round(now_timestamp - pre_timestamp, 4), len(data)))
						self.log_file_f.write(data)
						pre_timestamp = now_timestamp
						self.log_file_f.flush()
						self.log_time_f.flush()
						if self.term.input_mode:
							self.term.data += data		# 保存输入的命令
						data = ''
					except UnicodeDecodeError:
						pass
		except IndexError:
			pass

	def on_message(self, message):		# 客户端传输数据后开始调用该方法
		jsondata = json.loads(message)
		if not jsondata:
			return

		if 'resize' in jsondata.get('data'):		# 记录登录时发送的信息
			self.termlog.write(message)
			self.channel.resize_pty(
				width=int(jsondata.get('data').get('resize').get('cols', 100)),
				height=int(jsondata.get('data').get('resize').get('rows', 35))
			)
		elif jsondata.get('data'):		# web 浏览器与后台交互数据
			self.termlog.recoder = True
			self.term.input_mode = True
			if str(jsondata['data']) in ['\r', '\n', '\r\n']:		# 客户端输入回车后, 对输入的命令进行处理
				match = re.compile(r'\x1b\[\?1049', re.X).findall(self.term.vim_data)
				if match:
					if self.term.vim_flag or len(match) == 2:
						self.term.vim_flag = False
					else:
						self.term.vim_flag = True
				elif not self.term.vim_flag:
					result = self.term.deal_command(self.term.data)[0:200]
					if len(result) > 0:
						pass
				self.term.vim_data = ''
				self.term.data = ''
				self.term.input_mode = False
			self.channel.send(jsondata['data'])		# 将字符命令发送到远程连接的目标主机
		else:
			pass


class WebTerminalKillHandler(tornado.web.RequestHandler):
	pass


class ExecHandler(tornado.web.RequestHandler):
	pass


def main():
	from django.core.wsgi import get_wsgi_application
	import tornado.wsgi
	wsgi_app = get_wsgi_application()
	container = tornado.wsgi.WSGIContainer(wsgi_app)		# 将django application 封装到tornado WEB Server
	setting = {
		'cookie_secert': 'DFksdfsasdfkasdfFKwlwfsdfsa1204mx',		# tornado的安全cookie配置参数
		'template_path': os.path.join(os.path.dirname(__file__), 'templates'),		# tornado模板目录配置参数
		'static_path': os.path.join(os.path.dirname(__file__), 'static'),		# tornado静态文件目录配置参数
		'debug': False		# 关闭实时更新
	}

	tornado_app = tornado.web.Application(		# 创建一个tornado Application
		handlers=[
			(r'/ws/monitor', MonitorHandler),		# 通过正则表达式匹配到URL后映射的Handler
			(r'/ws/terminal', WebTerminalHandler),
			(r'/ws/kill', WebTerminalKillHandler),
			(r'/ws/exec', ExecHandler),
			(r'/static/(.*)', tornado.web.StaticFileHandler, dict(path=os.path.join(os.path.dirname(__file__), 'static'))),
			('.*', tornado.web.FallbackHandler, dict(fallback=container))
		],
		**setting
	)

	http_server = tornado.httpserver.HTTPServer(tornado_app)		# 创建http_server
	http_server.listen(options.port, address=options.host)		# 监听IP, PORT
	tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
	color_print('Run server on %s:%s' % (options.host, options.port), color='green')
	main()

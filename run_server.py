#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os.path
import functools
import tornado.options
import tornado.web
import tornado.ioloop
import tornado.httpserver
import tornado.websocket

from connect import logger
from mysite.settings import IP, PORT
from install.setup import color_print
from tornado.options import options, define
from django.core.signals import request_finished, request_started

# type=int表示参数类型是整型
define('port', default=PORT, help='run on the given port', type=int)		# 定义port参数, 通过options.port调用
define('host', default=IP, help='run port on given host', type=str)			# 定义host参数, 通过options.host调用


def django_request_support(func):
	@functools.wraps(func)		# 该装饰器作用是将原函数指定属性复制给包装函数
	def _deco(*args, **kwargs):
		result = request_started.send_robust(func)
		logger.debug(result)
		response = func(*args, **kwargs)
		request_finished.send_robust(func)
		return response

	return _deco


def require_auth(role='user'):
	def _deco(func):
		def _deco2(request, *args, **kwargs):
			if request.get_cookie('sessionid'):		# request等同于tornado实列self
				session_key = request.get_cookie('sessionid')		# 获取cookie
			else:
				session_key = request.get_argument('sessionid', '')		# tornado方法获取提交的参数值
			logger.debug('WebSocket: session_key: [ %s ]' % (session_key, ))
			return True
		return _deco2
	return _deco


class MonitorHandler(tornado.web.RequestHandler):
	pass


class WebTerminalHandler(tornado.websocket.WebSocketHandler):		# tornado websocket实现http长轮询
	clients = []
	tasks = []

	def __init__(self, *args, **kwargs):
		self.term = None
		self.log_file_f = None
		self.log_time_f = None
		self.log = None
		self.id = 0
		self.user = None
		self.ssh = None
		self.channel = None
		super(WebTerminalHandler, self).__init__(*args, **kwargs)

	def check_origin(self, origin):
		return True

	@django_request_support
	@require_auth('user')
	def open(self):		# 连接打开时该方法被调用
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

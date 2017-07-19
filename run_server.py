#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os.path
import tornado.options
import tornado.web
import tornado.ioloop
import tornado.httpserver
from mysite.settings import IP, PORT
from install.setup import color_print
from tornado.options import options, define

# type=int表示参数类型是整型
define('port', default=PORT, help='run on the given port', type=int)		# 定义port参数, 通过options.port调用
define('host', default=IP, help='run port on given host', type=str)			# 定义host参数, 通过options.host调用


class MonitorHandler(tornado.web.RequestHandler):
	pass


class WebTerminalHandler(tornado.web.RequestHandler):
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
			(r'/static/(.*)', tornado.web.StaticHandler, dict(path=os.path.join(os.path.dirname(__file__), 'static'))),
			('.*', tornado.web.FallbackHandler, dict(fallback=container))
		],
		**setting
	)

	http_server = tornado.httpserver.HTTPServer(tornado_app)		# 创建http_server
	http_server.listen(options.port, address=options.host)		# 监听IP, PORT
	tornado.ioloopIOLoop.instance().start()

if __name__ == '__main__':
	color_print('Run server on %s:%s' % (options.host, options.port), color='green')
	main()

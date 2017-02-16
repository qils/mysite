#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import tornado.options
from mysite.settings import IP, PORT
from install.setup import color_print
from tornado.options import options, define

define('port', default=PORT, help='run on the given port', type=int)
define('host', default=IP, help='run port on given host', type=str)

if __name__ == '__main__':
	color_print('Run server on %s:%s' % (options.host, options.port))
	main()
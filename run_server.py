#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import tornado.options
from install.setup import color_print
from tornado.options import options

if __name__ == '__main__':
	color_print('Run server on %s:%s' % (options.host, options.port))
	main()
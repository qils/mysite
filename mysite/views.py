#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from mysite.api import *


@require_role(role='user')
def index(request):
	pass


@defend_attack		# 登陆次数检查装饰器
def Login(request):
	pass

#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django.shortcuts import render, render_to_response

# Create your views here.
from juser.user_api import *


@defend_attack
def forget_password(request):
	if request.method == 'POST':
		pass
	else:
		error = '用户名不存在或邮件地址错误'

	return render_to_response('juser/forget_password.html', locals())
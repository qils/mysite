#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from mysite.api import *
from django.shortcuts import render_to_response
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login


# @require_role(role='user')
def index(request):
	return HttpResponse('OK')


@defend_attack		# 登陆次数检查装饰器, 会话没过期内,连续登陆时间不能超过10次
def Login(request):
	'''
	系统登陆界面视图
	'''
	error = ''		# 记录错误提示信息
	if request.user.is_authenticated():
		return HttpResponseRedirect(reverse('index'))
	if request.method == 'GET':
		return render_to_response('login.html')
	else:
		username = request.POST.get('username')
		password = request.POST.get('password')
		if username and password:
			user = authenticate(username=username, password=password)
			if user is not None:
				if user.is_active:
					login(request, user)
					if user.role == 'SU':
						request.session['role_id'] = 2
					elif user.role == 'GA':
						request.session['role_id'] = 1
					else:
						request.session['role_id'] = 0
					return HttpResponseRedirect(request.session.get('pre_url', '/'))
				else:
					error = '用户账户未激活'
			else:
				error = '用户名或密码错误'
		else:
			error = '用户名或密码错误'
	return render_to_response('login.html', {'error': error})

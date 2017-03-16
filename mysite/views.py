#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import datetime
from mysite.api import *
from django.shortcuts import render_to_response
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login


def getDaysByNum(num):
	'''
	返回所给出的num参数之前的日期
	'''
	today = datetime.date.today()
	oneday = datetime.timedelta(days=1)
	date_li, date_str = [], []
	for i in range(0, num):
		today = today - oneday
		date_li.append(today)
		date_str.append(str(today)[5:])
	date_li.reverse()
	date_str.reverse()
	return date_li, date_str


@require_role(role='user')
def index_cu(request):
	username = request.user.username
	return HttpResponseRedirect(reverse('user_detail'))


@require_role(role='user')		# 给视图添加访问权限
def index(request):
	li_date, li_str = getDaysByNum(7)
	today = datetime.datetime.now().day		# 当前日期
	from_week = datetime.datetime.now() - datetime.timedelta(days=7)		# 一周之前的日期

	if is_role_request(request, role='user'):		# 普通用户返回的视图
		return index_cu(request)
	elif is_role_request(request, role='super'):		# 超级用户返回的视图



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




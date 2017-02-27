#!/usr/bin/env python
# --*-- coding: utf-8 --*--
# Create your views here.

import time
from juser.user_api import *
from django.shortcuts import render, render_to_response

MAIL_FROM = settings.EMAIL_HOST_USER

@defend_attack
def forget_password(request):
	'''
	用户密码重置视图
	'''
	if request.method == 'POST':
		defend_attack(request)		# 暂时没找到这个函数调用的作用
		username = request.POST.get('username', '')
		name = request.POST.get('name', '')
		email = request.POST.get('email', '')
		user = get_object(User, username=username, email=email, name=name)		# 过滤是否有符合条件的User
		if user:
			timestamp = int(time.time())
			hash_encode = PyCrypt.md5_crypt(str(user.uuid) + str(timestamp) + settings.KEY)		# 通过uuid, 时间戳, settings配置文件中的KEY算一个md5
			msg = u'''
				Hi %s, 请点击下面的连接重设密码
				%s/juser/password/reset/?uuid=%s&timestamp=%s&hash=%s
			''' % (user.name, settings.URL, user.uuid, timestamp, hash_encode)
			try:
				send_mail('忘记跳板机密码', msg, MAIL_FROM, [email], fail_silently=False)		# fail_silently=False, 邮件发送失败触发异常
			except Exception, e:
				logger.error('邮件发送失败')
				return http_error(request, e)
			msg = '请登录邮箱, 点击连接重置密码'
			return http_success(request, msg)
		else:
			error = '用户名不存在或邮件地址错误'

	return render_to_response('juser/forget_password.html', locals())

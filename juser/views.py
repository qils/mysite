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
				logger.error('邮件发送失败: %s' % (e, ))		# 记录日志
				return http_error(request, '邮件发送失败')
			msg = '请登录邮箱, 点击连接重置密码'
			return http_success(request, msg)
		else:
			error = '用户名不存在或邮件地址错误'

	return render_to_response('juser/forget_password.html', locals())


@defend_attack
def reset_password(request):
	'''
	密码重置视图
	'''
	uuid_r = request.GET.get('uuid', '')
	timestamp = request.GET.get('timestamp', '')
	hash_encode = request.GET.get('hash', '')
	action = '/juser/password/reset/?uuid=%s&timestamp=%s&hash=%s' % (uuid_r, timestamp, hash_encode)

	if hash_encode == PyCrypt.md5_crypt(uuid_r + timestamp + settings.KEY):
		if int(time.time()) - int(timestamp) >= 600:		# 时间超过600秒后连接超时, 需重新生成连接
			return HttpResponse('连接已超时')
	else:
		return HttpResponse('hash校验失败')

	if request.method == 'POST':
		new_password = request.POST.get('password', '')
		password_confirm = request.POST.get('password_confirm', '')
		if new_password != password_confirm:
			return http_error(request, '两次输入的密码不匹配, 请重新输入')
		user = get_object(User, uuid=uuid_r)
		if user:
			user.set_password(new_password)
			user.save()
			logger.info(u'用户[%s]更新密码成功' % (user.username, ))		# 记录密码变更的用户
			return http_success(request, '密码重置成功')
		else:
			return HttpResponse('用户不存在')
	else:
		return render_to_response('juser/reset_password.html', locals())

	return http_error(request, '请求错误')		# 这个不会被调用到


def group_list(request):
	pass


def user_list(request):
	pass


def user_detail(request):
	pass


@require_role(role='user')
def profile(request):
	'''
	用户个人信息视图函数
	'''
	user_id = request.user.id
	if not user_id:
		return HttpResponseRedirect(reverse('index'))
	user = User.objects.filter(id=user_id)
	return my_render('juser/profile.html', locals(), request)


def change_info(request):
	pass

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


@require_role(role='super')
def group_list(request):
	'''
	用户组列表视图
	'''
	header_title, path1, path2 = '查看用户组', '用户管理', '查看用户组'
	keyword = request.GET.get('search', '')
	user_group_list = UserGroup.objects.all().order_by('name')
	group_id = request.GET.get('id', '')

	user_group_list, p, user_groups, page_range, current_page, show_first, show_end = pages(user_group_list, request)
	return my_render('juser/group_list.html', locals(), request)


@require_role(role='super')
def user_list(request):
	'''
	查看所有用户视图
	'''
	user_role = {'SU': '超级管理员', 'GA': '组管理员', 'CU': '普通用户'}
	header_title, path1, path2 = '查看用户', '用户管理', '用户列表'
	keyword = request.GET.get('keyword', '')
	gid = request.GET.get('gid', '')
	users_list = User.objects.all().order_by('username')

	users_list, p, users, page_range, current_page, show_first, show_end = pages(users_list, request)
	return my_render('juser/user_list.html', locals(), request)


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
	user = User.objects.get(id=user_id)
	return my_render('juser/profile.html', locals(), request)


def change_info(request):
	'''
	用户信息修改视图
	'''
	header_title, path1, path2 = '修改信息', '用户管理', '修改个人信息'
	user_id = request.user.id
	user = User.objects.get(id=user_id)
	error = ''

	if not user:
		return HttpResponseRedirect(reverse('index'))

	if request.method == 'POST':
		name = request.POST.get('name', '')
		password = request.POST.get('password', '')
		email = request.POST.get('email', '')

		if '' in [name, email]:
			error = '姓名或者邮件地址为空'

		if not error:
			user.name = name
			user.email = email
			user.save()
			if len(password) > 0:
				user.set_password(password)
				user.save()
			msg = '用户信息修改成功'
	return my_render('juser/change_info.html', locals(), request)


@require_role(role='user')
def regen_ssh_key(request):
	uuid_r = request.GET.get('uuid', '')
	user = get_object(User, uuid=uuid_r)
	if not user:
		return HttpResponse('用户不存在')

	username = user.username
	ssh_key_pass = PyCrypt.gen_rand_key(16)		# 随机生成的16位字符的密码
	gen_ssh_key(username, ssh_key_pass)		# 生成秘钥对
	return HttpResponse('ssh密钥已生成，密码为 %s, 请到下载页面下载' % (ssh_key_pass, ))


@require_role(role='super')
def user_add(request):
	'''
	添加用户视图
	'''
	error = ''
	msg = ''
	header_title, path1, path2 = '添加用户', '用户管理', '添加用户'
	user_role = {'SU': '超级管理员', 'CU': '普通用户'}
	group_all = UserGroup.objects.all()

	if request.method == 'POST':
		pass

	return my_render('juser/user_add.html', locals(), request)


def down_key(request):
	pass


def user_edit(request):
	pass


def user_del(request):
	pass


def send_mail_retry(request):
	pass


@require_role(role='super')
def group_add(request):
	'''
	添加用户组视图
	'''
	error = ''
	msg = ''
	header_title, path1, path2 = '添加用户组', '用户管理', '添加用户组'
	user_all = User.objects.all()

	if request.method == 'POST':
		group_name = request.POST.get('group_name', '')
		users_selected = request.POST.getlist('users_selected', [])		# 返回的是由select option标签中value值组成的列表
		comment = request.POST.get('comment', '')

		try:
			if not group_name:
				error = '输入的用户组为空'
				raise ServerError(error)

			if get_object(UserGroup, name=group_name):
				error = '用户组已存在'
				raise ServerError(error)
			db_add_group(name=group_name, users_id=users_selected, comment=comment)		# 往用户组表中插入一条记录
		except ServerError:
			pass
		except TypeError:
			error = '添加用户组失败'
		else:
			msg = '添加用户组成功'

	return my_render('juser/group_add.html', locals(), request)


def group_del(request):
	pass


def group_edit(request):
	pass

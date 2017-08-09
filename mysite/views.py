#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
import datetime
from mysite.api import *
from django.shortcuts import render_to_response
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login, logout
from jasset.models import Asset, IDC
from jlog.models import Log, FileLog
from django.utils import timezone
from django.db.models import Count
from django.template import RequestContext
from mysite.models import Setting


def getDaysByNum(num):
	'''
	返回所给出的num参数之前的日期, 不包含当前日期
	'''
	today = datetime.date.today()
	oneday = datetime.timedelta(days=1)
	date_li, date_str = [], []
	for i in range(0, num):
		today = today - oneday
		date_li.append(today)		# 保存一个星期前的日期, 格式为年, 月, 日
		date_str.append(str(today)[5:])		# 保存一个星期前的日期, 格式为月, 日
	date_li.reverse()
	date_str.reverse()
	return date_li, date_str


def get_data_by_day(date_li, item):
	data_li = []
	for d in date_li:
		logs = Log.objects.filter(
			start_time__year=d.year,
			start_time__month=d.month,
			start_time__day=d.day
		)
		if item == 'user':
			data_li.append(set([log.user for log in logs]))		# 去重同一个用户记录
		elif item == 'asset':
			data_li.append(set([log.host for log in logs]))		# 去重同一个资产记录
		elif item == 'login':
			data_li.append(logs)
		else:
			pass
	return data_li


def get_count_by_day(date_li, item):
	data_li = get_data_by_day(date_li, item)
	data_count_li = []
	for data in data_li:
		data_count_li.append(len(data))		# 计算每天的日志条数,去重之后的, 活跃用户,活跃资产去重, 登录日志没有去重
	return data_count_li


def get_count_by_date(date, item):
	'''
	一个月内登录的用户, 或者是登录的资产记录
	'''
	logs = Log.objects.filter(start_time__gt=date)
	if item == 'user':
		return logs.values('user').distinct().count()
	elif item == 'asset':
		return logs.values('host').distinct().count()
	else:
		pass


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
		users = User.objects.all()		# 所有账号
		hosts = Asset.objects.all()		# 所有资产
		online = Log.objects.filter(is_finished=0)		# 在线登录的用户, is_finished为0, 表示在线用户
		online_host = online.values('host').distinct()		# values()获取host列所有数据, distinct()暂时没法去重相同的数据
		online_user = online.values('user').distinct()		# 同上, 所有在线用户的记录
		active_users = User.objects.filter(is_active=1)		# 所有激活的账号
		active_hosts = Asset.objects.filter(is_active=1)		# 所有激活的主机

		# 一个月历史汇总信息, 从Log模型中过滤数据
		date_li, date_str = getDaysByNum(30)
		days_before_30 = timezone.now() + timezone.timedelta(days=-30)
		date_month = repr(date_str)		# 前一个月的日期, 格式为, 年, 月, 日
		active_user_per_month = str(get_count_by_day(date_li, 'user'))		# 一个月内每天登陆的用户数量(去重后)
		active_asset_per_month = str(get_count_by_day(date_li, 'asset'))		# 一个月内每天登陆的设备数量(去重后)
		active_login_per_month = str(get_count_by_day(date_li, 'login'))		# 一个月内每天的登录日志

		# 一个月内活跃用户,资产图
		active_user_month = get_count_by_date(days_before_30, 'user')
		disabled_user_count = len(users.filter(is_active=False)) if users.filter(is_active=False) else 0		# 未激活用户数量
		inactive_user_month = len(users) - active_user_month		# 一个月内的非活跃用户数量
		active_asset_month = get_count_by_date(days_before_30, 'asset')
		disabled_asset_count = len(hosts.filter(is_active=False)) if hosts.filter(is_active=False) else 0		# 未激活的主机数
		inactive_asset_month = len(hosts) - active_asset_month if len(hosts) > active_asset_month else 0

		# 一周top10用户和主机
		week_data = Log.objects.filter(start_time__range=[from_week, datetime.datetime.now()])		# 一周之内的日志
		user_top_ten = week_data.values('user').annotate(times=Count('user')).order_by('-times')[:10]		# 倒序排列取前十登录用户数
		host_top_ten = week_data.values('host').annotate(times=Count('host')).order_by('-times')[:10]		# 取前十被访问的主机

		for user_info in user_top_ten:		# 增加最后一次登录日期
			username = user_info.get('user')
			last = Log.objects.filter(user=username).latest('start_time')
			user_info['last'] = last

		for host_info in host_top_ten:
			host = host_info.get('host')
			last = Log.objects.filter(host=host).latest('start_time')		# 取最后一次登录设备的记录
			host_info['last'] = last

		# 一周top5
		week_users = week_data.values('user').distinct().count()		# 去重后一周内用户登录数
		week_hosts = week_data.count()		# 总数量

		user_top_five = week_data.values('user').annotate(times=Count('user')).order_by('-times')[:5]		# 取前5登录次数最多的用户
		color = ['label-success', 'label-info', 'label-primary', 'label-default', 'label-warnning']

		# 最后10次登录
		login_10 = Log.objects.order_by('-start_time')[:10]
		login_more_10 = Log.objects.order_by('-start_time')[10:21]
	return render_to_response('index.html', locals(), context_instance=RequestContext(request))


@defend_attack		# 登陆次数检查装饰器, 会话没过期内,连续登陆时间不能超过10次
def Login(request):
	'''
	系统登陆界面视图
	'''
	error = ''		# 记录错误提示信息
	if request.user.is_authenticated():		# 判断用户是否通过验证
		return HttpResponseRedirect(reverse('index'))
	if request.method == 'GET':
		return render_to_response('login.html')
	else:
		username = request.POST.get('username')		# 获取登录的账号
		password = request.POST.get('password')		# 获取登录的账号密码
		if username and password:
			user = authenticate(username=username, password=password)		# 验证用户名, 密码是否正确,正确返回user对象
			if user is not None:
				if user.is_active:		# 检查用户是否激活
					login(request, user)
					if user.role == 'SU':
						request.session['role_id'] = 2
					elif user.role == 'GA':
						request.session['role_id'] = 1
					else:
						request.session['role_id'] = 0
					return HttpResponseRedirect(request.session.get('pre_url', '/'))		# pre_url保存前一次的request.path
				else:
					error = '用户账户未激活'
			else:
				error = '用户名或密码错误'
		else:
			error = '用户名或密码错误'
	return render_to_response('login.html', {'error': error})


def upload(request):
	pass


def download(request):
	pass


@require_role('admin')
def setting(request):
	'''
	默认配置视图, 支持配置用户名,密码或者配置一个私钥
	'''
	header_title, path1 = u'项目设置', u'设置'
	setting_default = get_object(Setting, name='default')
	if request.method == 'POST':
		try:
			if request.POST.get('setting', '') == 'default':
				username = request.POST.get('username', '')		# 默认用户名
				password = request.POST.get('password', '')		# 默认密码
				port = request.POST.get('port', '')		# 默认连接的端口号
				private_key = request.POST.get('key', '')

				if not password and not private_key:
					raise ServerError('密码或者私钥,两个必填一个')

				if len(password) > 30:
					raise ServerError('密码长度不能超过30字符')

				private_key_dir = os.path.join(settings.BASE_DIR, 'keys', 'default')		# 私钥存放目录
				private_key_path = os.path.join(private_key_dir, 'admin_user.pem')		# 私钥文件路径
				mkdir(private_key_dir)
				if private_key:		# 如果输入私钥, 就写入到文件
					with open(private_key_path, 'w') as f:
						f.write(private_key)
					os.chmod(private_key_path, 0600)

				if setting_default:
					if password:		# 表示密码重新修改过
						password_encode = CRYPTOR.encrypt(password)		# 重新加密密码后存储到setting表
					else:
						password_encode = password		# 表示密码没有重新修改
					Setting.objects.filter(name='default').update(
						field1=username,
						field2=port,
						field3=password_encode,
						field4=private_key_path
					)
				else:
					password_encode = CRYPTOR.encrypt(password)
					Setting(
						name='default',
						field1=username,
						field2=port,
						field3=password_encode,
						field4=private_key_path,
					).save()
				msg = '默认设置成功'
		except ServerError as e:
			error = e.message

	return my_render('setting.html', locals(), request)


@require_role('user')
def web_terminal(request):
	'''
	web_terminal web界面登录资产视图
	'''
	asset_id = request.GET.get('id', '')
	role_name = request.GET.get('role', '')
	asset = get_object(Asset, id=asset_id)
	if asset:
		hostname = asset.hostname

	return render_to_response('jlog/web_terminal.html', locals())


def exec_cmd(request):
	pass


@require_role(role='user')
def Logout(request):
	logout(request)
	return HttpResponseRedirect(reverse('index'))


def skin_config(request):
	'''
	更换页面皮肤视图
	'''
	return render_to_response('skin_config.html')




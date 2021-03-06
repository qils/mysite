#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
import datetime
import zipfile
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

from jperm.perm_api import get_group_user_perm, gen_resource
from jperm.ansible_api import MyRunner


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


@require_role(role='user')
def upload(request):
	'''
	页面上传文件视图
	'''
	path1 = u'上传文件'
	user = request.user		# 登录用户对象
	assets = get_group_user_perm(user).get('asset').keys()		# 获取用户授权的所有资产
	asset_select = []

	if request.method == 'POST':
		remote_ip = request.META.get('REMOTE_ADDR')		# 获取远程上传的客户端IP
		asset_ids = request.POST.getlist('asset_ids', [])		# 获取用户选择上传的资产id
		upload_files = request.FILES.getlist('file[]', [])		# 获取用户上传的文件对象
		date_now = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
		upload_dir = get_tmp_dir()

		for asset_id in asset_ids:
			asset_select.append(get_object(Asset, id=asset_id))

		if not set(asset_select).issubset(set(assets)):		# 选择上传的资产必须是授权资产的子集
			illegal_asset = list(set(asset_select) - set(assets))		# 这里和源码里面不一样
			return HttpResponse(u'非法的资产: %s' % (','.join([asset.hostname for asset in illegal_asset])))

		for upload_file in upload_files:
			file_path = '%s/%s' % (upload_dir, upload_file.name)
			with open(file_path, 'w') as f:		# 将上传的文件写入服务器的随机生成的/tmp目录
				for chunk in upload_file.chunks():
					f.write(chunk)

		res = gen_resource({'user': user, 'asset': asset_select})
		runner = MyRunner(res)
		runner.run('copy', module_args='src=%s dest=%s directory_mode' % (upload_dir, '/tmp/'), pattern='*')		# 上传到目标资产会多一层目录
		ret = runner.results
		logger.debug(ret)

		FileLog(
			user=user.username,
			host=' '.join([asset.hostname for asset in asset_select]),		# 记录上传的主机名
			filename=', '.join([f.name for f in upload_files]),
			type='upload',
			remote_ip=remote_ip,
			result=ret
		).save()

		if ret.get('failed'):
			error = u'上传目录: %s<br>上传失败: [ %s ]<br>上传成功: [%s]' % (upload_dir, ', '.join(ret.get('failed').keys()), ', '.join(ret.get('ok').keys()))
			return HttpResponse(error, status=500)

		msg = u'上传目录: [ %s ]<br>传送成功: [ %s ]' % (upload_dir, ', '.join(ret.get('ok').keys()))
		return HttpResponse(msg)

	return my_render('upload.html', locals(), request)


@require_role(role='user')
def download(request):
	'''
	文件下载视图
	'''
	path1 = u'文件下载'
	user = request.user
	assets = get_group_user_perm(user).get('asset').keys()		# 授权所有资产
	asset_select = []		# 定义选择下载的目标资产

	if request.method == 'POST':
		remote_ip = request.META.get('REMOTE_ADDR')
		asset_ids = request.POST.getlist('asset_ids', [])
		file_path = request.POST.get('file_path')
		download_dir = get_tmp_dir()
		date_now = datetime.datetime.now().strftime('%Y%m%d%H%M%S')

		for asset_id in asset_ids:
			asset_select.append(get_object(Asset, id=asset_id))

		if not set(asset_select).issubset(set(assets)):
			illegal_asset = list(set(asset_select) - set(assets))
			return HttpResponse(u'没有授权的服务器: %s' % (', '.join([asset.hostname for asset in illegal_asset])))

		res = gen_resource({'user': user, 'asset': asset_select})
		runner = MyRunner(res)
		runner.run('fetch', module_args='src=%s dest=%s' % (file_path, download_dir), pattern='*')		# 从目标资产下载文件, 文件存储路径包括每台主机名称
		logger.debug(runner.results)
		FileLog(
			user=user.username,
			host=' '.join([asset.hostname for asset in asset_select]),
			filename=file_path,
			type='download',
			remote_ip=remote_ip,
			result=runner.results
		).save()

		tmp_dir_name = os.path.basename(download_dir)
		file_zip = os.path.join('/tmp', tmp_dir_name, '.zip')
		zf = zipfile.ZipFile(file_zip, 'w', zipfile.ZIP_DEFLATED)		# 创建ZIP文件
		for dirname, subdirs, files in os.walk(download_dir):
			zf.write(dirname)		# 增加压缩包目录信息 download_dir + hostname + /tmp/
			for filename in files:
				zf.write(os.path.join(dirname, filename))
		zf.close()

		f = open(file_zip)
		data = f.read()
		f.close()
		response = HttpResponse(data, content_type='application/octet-stream')
		response['Content-Disposition'] = 'attachment; filename=%s.zip' % (tmp_dir_name, )
		return response

	return my_render('download.html', locals(), request)


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
						password_encode = setting_default.field3		# 表示密码没有重新修改
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




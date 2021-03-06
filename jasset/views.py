#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django.shortcuts import render
from mysite.api import *
from django.db.models import Q
from jasset.models import AssetGroup, Asset, IDC, ASSET_TYPE, ASSET_STATUS, ASSET_ENV
from jasset.asset_api import *
from jasset.forms import IdcForm, AssetForm
from jperm.perm_api import get_group_asset_perm, get_group_user_perm
from mysite.models import Setting
# Create your views here.


@require_role('admin')
def group_list(request):
	'''
	资产组表视图
	'''
	header_title, path1, path2 = u'查看资产组', u'资产管理', u'查看资产组'
	asset_group_list = AssetGroup.objects.all()		# 过滤所有资产组名
	keyword = request.GET.get('keyword', '')
	group_id = request.GET.get('id', '')
	if group_id:
		asset_group_list = asset_group_list.filter(id=group_id)

	if keyword:
		asset_group_list = asset_group_list.filter(Q(name__icontains=keyword) | Q(comment__icontains=keyword))

	asset_group_list, p, asset_groups, page_range, current_page, show_first, show_end = pages(asset_group_list, request)
	return my_render('jasset/group_list.html', locals(), request)


@require_role('admin')
def group_add(request):
	'''
	添加主机组视图
	'''
	header_title, path1, path2 = u'添加资产组', u'资产管理', u'添加资产组'
	asset_all = Asset.objects.all()		# 过滤所有资产

	if request.method == 'POST':
		name = request.POST.get('name', '')		# 获取主机组名称
		asset_select = request.POST.getlist('asset_select', [])		# 获取往主机组中所添加的主机, 返回由所有选择的主机ID组成的列表
		comment = request.POST.get('comment', '')

		try:
			if not name:
				emg = u'主机组名不能为空'
				raise ServerError(emg)

			asset_group_test = get_object(AssetGroup, name=name)		# 检测主机组是否存在
			if asset_group_test:
				emg = u'组名 %s 已存在' % (name, )
				raise ServerError(emg)
		except ServerError:
			pass
		else:
			db_add_group(name=name, comment=comment, asset_select=asset_select)
			msg = u'主机组 %s 添加成功' % (name, )

	return my_render('jasset/group_add.html', locals(), request)


@require_role('admin')
def group_edit(request):
	'''
	编辑资产组视图
	'''
	emg = ''
	header_title, path1, path2 = u'编辑主机组', u'资产管理', u'编辑主机组'
	group_id = request.GET.get('id', '')
	group = get_object(AssetGroup, id=group_id)

	asset_all = Asset.objects.all()		# 筛选所有主机资产
	asset_select = Asset.objects.filter(group=group)		# 筛选添加到资产组中的主机
	asset_no_select = [a for a in asset_all if a not in asset_select]

	if request.method == 'POST':
		name = request.POST.get('name', '')
		asset_select = request.POST.getlist('asset_select', [])
		comment = request.POST.get('comment', '')

		try:
			if not name:
				emg = u'资产组名不能为空'
				raise ServerError(emg)

			if group.name != name:		# 资产组名修改后检测修改后的名称是否和已存在的名称有冲突
				asset_group_test = get_object(AssetGroup, name=name)
				if asset_group_test:
					emg = u'资产组名 %s 已经存在' % (name, )
					raise ServerError(emg)
		except ServerError:
			pass
		else:
			group.asset_set.clear()		# 清除资产组中的所有资产主机
			db_update_group(id=group_id, name=name, comment=comment, asset_select=asset_select)
			msg = u'主机组 %s 编辑成功' % (name, )

		if not emg:
			return HttpResponseRedirect(reverse('asset_group_list'))
	return my_render('jasset/group_edit.html', locals(), request)


@require_role('admin')
def group_del(request):
	'''
	删除资产组视图
	'''
	group_ids = request.GET.get('id', '')
	group_id_list = group_ids.split(',')

	for group_id in group_id_list:
		asset_group = AssetGroup.objects.filter(id=group_id)
		if asset_group:
			asset_group.delete()

	return HttpResponse(u'删除成功')


@require_role('admin')
def asset_add(request):
	'''
	添加资产视图
	'''
	header_title, path1, path2 = u'添加资产', u'资产管理', u'添加资产'
	asset_group_all = AssetGroup.objects.all()		# 过滤所有资产组
	af = AssetForm()		# 资产表单域
	default_setting = get_object(Setting, name='default')
	default_port = default_setting.field2 if default_setting else ''		# 默认登录端口

	if request.method == 'POST':
		af_post = AssetForm(request.POST)		# 创建一个AssetForm 实列
		hostname = request.POST.get('hostname', '')		# 资产名称
		ip = request.POST.get('ip', '')		# 资产IP地址
		is_active = True if request.POST.get('is_active') == '1' else False
		use_default_auth = request.POST.get('use_default_auth', '')

		try:
			if Asset.objects.filter(hostname=unicode(hostname)):		# 检验是否有重名的hostname
				error = u'该主机名 %s 已经存在' % (hostname, )
				raise ServerError(error)
			if len(hostname) > 54:
				error = u'主机名长度不能超过54'
				raise ServerError(error)
		except ServerError:
			pass
		else:
			if af_post.is_valid():		# 验证提交的数据是否有效
				asset_save = af_post.save(commit=False)		# commit=False, 避免Model实列立即存储到数据库
				if not use_default_auth:		# 不使用默认管理账号
					password = request.POST.get('password', '')
					password_encode = CRYPTOR.encrypt(password)		# 对称加密提交的密码
					asset_save.password = password_encode
				if not ip:		# 当没有输入主机IP时, 设置主机IP为主机名
					asset_save.ip = hostname
				asset_save.is_active = is_active if is_active else False
				asset_save.save()		# 存储ModelForm实列到数据库
				af_post.save_m2m()		# 当使用commit=False, 需要手动调用save_m2m()来存储多对多字段内容
				msg = u'主机 %s 添加成功' % (hostname, )
			else:
				error = u'主机 %s 添加失败' % (hostname, )
			return HttpResponseRedirect(reverse('asset_list'))

	return my_render('jasset/asset_add.html', locals(), request)


@require_role('admin')
def asset_detail(request):
	'''
	资产详细信息视图
	'''
	header_title, path1, path2 = u'主机详细信息', u'资产管理', u'主机详情'
	asset_id = request.GET.get('id', '')
	asset = get_object(Asset, id=asset_id)
	perm_info = get_group_asset_perm(asset)
	log = Log.objects.filter(host=asset.hostname).order_by('-start_time')		# 过滤主机登录日志
	if perm_info:
		user_perm = []
		for perm, value in perm_info.items():
			if perm == 'user':
				for user, role_dic in value.items():
					user_perm.append([user, role_dic.get('role', '')])
			elif perm == 'user_group':
				user_group_perm = value
			elif perm == 'rule':		# 源码中没有这个判断
				user_rule_perm = value

	asset_record = AssetRecord.objects.filter(asset=asset).order_by('-alert_time')		# 资产变更记录

	return my_render('jasset/asset_detail.html', locals(), request)


@require_role(role='admin')
def asset_update(request):
	'''
	更新资产视图
	'''
	asset_id = request.GET.get('id', '')
	asset = get_object(Asset, id=asset_id)
	name = request.user.username

	if not asset:
		return HttpResponseRedirect(reverse('asset_detail') + '?id=%s' % (asset_id, ))
	else:
		asset_ansible_update([asset], name)
	return HttpResponseRedirect(reverse('asset_detail') + '?id=%s' % (asset_id, ))


@require_role(role='super')
def asset_edit(request):
	'''
	资产主机编辑视图
	'''
	header_title, path1, path2 = u'修改资产', u'资产管理', u'修改资产'
	asset_id = request.GET.get('id', '')
	username = request.user.username
	asset = get_object(Asset, id=asset_id)
	if asset:
		password_old = asset.password		# 保留设备管理用户名password
		username_old = asset.username		# 保留设备管理用户名, 资产变更时, 记录变更到使用默认管理用户时的用户名
	af = AssetForm(instance=asset)		# 校验表单数据,指定了instance实列, 后续所有修改都做用在这个实列(asset)上
	if request.method == 'POST':
		af_post = AssetForm(request.POST, instance=asset)		# 加载数据优先级request.POST > instance
		ip = request.POST.get('ip', '')
		hostname = request.POST.get('hostname', '')
		password = request.POST.get('password', '')
		is_active = True if request.POST.get('is_active') == '1' else False
		use_default_auth = request.POST.get('use_default_auth', '')		# 使用默认该值为字符no, 不使用默认该值为空字符
		try:
			asset_test = get_object(Asset, hostname=hostname)
			if asset_test and asset_id != unicode(asset_test.id):		# 检验是否有重名的主机名
				emg = u'主机名 %s 冲突' % (hostname, )
				raise ServerError(emg)
			if len(hostname) > 54:
				emg = u'主机名长度不能超过54个字符'
				raise ServerError(emg)
			else:
				if af_post.is_valid():		# 检验数据是否有效
					af_save = af_post.save(commit=False)		# commit=False避免立即存储到数据库
					if use_default_auth:		# 是否使用默认管理用户, 如果使用默认用户名, 密码留空, 如果不使用, 判断密码是否有更改
						af_save.username = ''		# 当使用默认时, 编辑完后username在数据表中会变为空
						af_save.password = ''
					else:
						if password:
							password_encode = CRYPTOR.encrypt(password)
							af_save.password = password_encode
						else:
							af_save.password = password_old		# 密码不修改还是原来的旧密码
					af_save.is_active = True if is_active else False
					af_save.save()
					af_post.save_m2m()		# 存储对多对数据

					info = asset_diff(af_post.__dict__.get('initial'), request.POST)		# 对比更新资产信息前,后差异
					db_asset_alert(asset, username, info, username_old)		# 将变更信息记录到AssetRecord表
					msg = u'主机 %s 修改成功' % (ip, )
				else:
					emg = u'主机 %s 修改失败' %(ip, )
					raise ServerError(emg)
		except ServerError as e:
			error = e.message
			return my_render('jasset/asset_edit.html', locals(), request)
		return HttpResponseRedirect(reverse('asset_detail') + '?id=%s' % (asset.id, ))

	return my_render('jasset/asset_edit.html', locals(), request)


@require_role('admin')
def asset_del(request):
	'''
	删除资产主机视图
	'''
	asset_id = request.GET.get('id', '')
	if asset_id:
		Asset.objects.filter(id=asset_id).delete()

	if request.method == 'POST':		# 批量删除资产主机记录
		asset_batch = request.GET.get('arg', '')
		asset_id_all = str(request.POST.get('asset_id_all', ''))
		if asset_batch:
			asset_id_all = asset_id_all.split(',')
			for asset_id in asset_id_all:
				asset = get_object(Asset, id=asset_id)
				if asset:
					asset.delete()

	return HttpResponse('删除成功')


@require_role('admin')
def asset_edit_batch(request):
	'''
	批量修改资产视图
	'''
	af = AssetForm()
	name = request.user.username
	asset_group_all = AssetGroup.objects.all()

	if request.method == 'POST':
		env = request.POST.get('env', '')
		idc_id = request.POST.get('idc', '')
		port = request.POST.get('port', '')
		use_default_auth = request.POST.get('use_default_auth', '')
		username = request.POST.get('username', '')
		password = request.POST.get('password', '')
		group = request.POST.getlist('group', [])
		cabinet = request.POST.get('cabinet', '')
		comment = request.POST.get('comment', '')
		asset_id_all = unicode(request.GET.get('asset_id_all', ''))		# 从URL参数中获取需要变更的资产ID
		asset_id_all = asset_id_all.split(',')
		for asset_id in asset_id_all:		# 循环对需要修改的资产进行更改
			alert_info = []		# 保存变更前后信息
			asset = get_object(Asset, id=asset_id)
			if asset:
				if env:		# 运行环境变更处理
					if asset.env != int(env):		# 增加类型转换, 提交的env为字符整型
						env_all = {1: u'生产环境', 2: u'测试环境'}
						old_env = asset.env
						asset.env = env
						alert_info.append([u'运行环境', env_all.get(old_env, ''), env_all.get(int(env), '')])
				if idc_id:		# 机房变更处理
					idc = get_object(IDC, id=idc_id)
					name_old = asset.idc.name if asset.idc else u''
					if idc and idc.name != name_old:
						asset.idc = idc
						alert_info.append([u'机房名称', name_old, idc.name])
				if port:		# 端口变更处理
					if int(port) != asset.port:		# 增加类型转换, 提交的port为字符整型
						old_port = asset.port
						asset.port = port
						alert_info.append([u'端口号', old_port, port])
				if use_default_auth:		# 使用默认管理账号变更处理
					if use_default_auth == 'default':
						asset.use_default_auth = 1
						old_username = asset.username
						asset.username = ''
						asset.password = ''
						alert_info.append([u'使用默认管理账号', old_username, u'默认'])
					elif use_default_auth == 'user_passwd':
						asset.use_default_auth = 0
						asset.username = username
						password_encode = CRYPTOR.encrypt(password)
						asset.password = password_encode
						alert_info.append([u'使用默认管理账号', u'默认', username])
				if group:		# 资产组变更
					group_new, group_old, group_new_name, group_old_name = [], asset.group.all(), [], []
					for group_id in group:
						asset_group = get_object(AssetGroup, id=group_id)
						if asset_group:
							group_new.append(asset_group)
					if not set(group_new) < set(group_old):		# 新资产组是否是旧资产组的子集, 是的话不记录组变更信息
						group_instance = list(set(group_new) | set(group_old))		# 新, 旧资产组求集合
						for asset_group in group_new:		# 源码这里用的是group_instance, 新的资产组包括旧的资产组
							group_new_name.append(asset_group.name)
						for asset_group in group_old:
							group_old_name.append(asset_group.name)
						asset.group = group_new
						alert_info.append([u'主机组', '|'.join(group_old_name), '|'.join(group_new_name)])
				if cabinet:
					if asset.cabinet != cabinet:
						old_cabinet = asset.cabinet
						asset.cabinet = cabinet
						alert_info.append([u'机柜号', old_cabinet, cabinet])
				if comment:
					if asset.comment != comment:
						old_comment = asset.comment
						asset.comment = comment
						alert_info.append([u'备注', old_comment, comment])
				asset.save()
			if alert_info:
				recode_name = unicode(name) + ' - ' + u'批量'
				AssetRecord.objects.create(asset=asset, username=recode_name, content=alert_info)
		return my_render('jasset/asset_update_status.html', locals(), request)
	return my_render('jasset/asset_edit_batch.html', locals(), request)


@require_role(role='admin')
def asset_update_batch(request):
	'''
	批量更新资产物理硬件信息视图
	'''
	if request.method == 'POST':
		asset_list = []
		arg = request.GET.get('arg', '')
		name = unicode(request.user.username) + ' - ' + u'自动更新'
		if arg == 'all':		# 更新所有资产的物理硬件信息
			asset_list = Asset.objects.all()
		else:
			asset_id_all = unicode(request.POST.get('asset_id_all', ''))
			asset_id_all = asset_id_all.split(',')
			for asset_id in asset_id_all:
				asset = get_object(Asset, id=asset_id)
				if asset:
					asset_list.append(asset)
		asset_ansible_update(asset_list, name)
		return HttpResponse(u'批量更新成功')
	return HttpResponse(u'批量更新成功')


@require_role('admin')
def asset_upload(request):
	'''
	上传的资产excel文件处理视图
	'''
	if request.method == 'POST':
		excel_file = request.FILES.get('file_name', '')
		ret = excel_to_db(excel_file)		# 批量往资产表中添加资产
		if ret:
			msg = u'批量添加成功'
		else:
			emg = u'批量添加失败, 请检查格式!!!'

	return my_render('jasset/asset_add_batch.html', locals(), request)


@require_role('admin')
def asset_add_batch(request):
	'''
	批量增加资产视图
	'''
	header_title, path1, path2 = u'添加资产', u'资产管理', u'批量添加'
	return my_render('jasset/asset_add_batch.html', locals(), request)


@require_role('user')
def asset_list(request):
	'''
	主机资产视图
	'''
	header_title, path1, path2 = u'查看资产', u'资产管理', u'查看资产'
	username = request.user.username
	user_perm = request.session['role_id']		# 用户权限, 2: SU, 1: GA, 0: CU

	idc_all = IDC.objects.filter().order_by('name')		# 过滤所有的IDC信息
	asset_group_all = AssetGroup.objects.all()		# 过滤所有的资产组信息
	asset_types = ASSET_TYPE		# 资产类型, 定义7种资产类型
	asset_status = ASSET_STATUS		# 资产状态, 三种状态: 已上线, 未上线, 已下架

	idc_name = request.GET.get('idc', '')		# 从表单里面提交
	group_name = request.GET.get('group', '')		# 从表单里面提交
	asset_type = request.GET.get('asset_type', '')		# 从表单提交
	status = request.GET.get('status', '')		# 从表单提交
	keyword = request.GET.get('keyword', '')		# 从表单提交
	export = request.GET.get('export', False)		# 从表单提交
	asset_id_all = request.GET.getlist('id', [])		# 获取所提交的所有资产

	group_id = request.GET.get('group_id', '')		# 在资产组中, 每一个资产组所关联的资产, 由group_id查询参数连接
	idc_id = request.GET.get('idc_id', '')		# 在IDC中, 每一个IDC所关联的资产, 由idc_id查询参数连接
	asset_id = request.GET.get('id', '')		# 从用户授权的资产记录连接过来的资产

	if group_id:		# 从资产组过来的连接
		group = get_object(AssetGroup, id=group_id)
		if group:
			asset_find = Asset.objects.filter(group=group)
	elif idc_id:		# 从IDC过来的连接
		idc = get_object(IDC, id=idc_id)
		if idc:
			asset_find = Asset.objects.filter(idc=idc)
	elif asset_id:		# 源码没有加入这个条件
		asset_find = Asset.objects.filter(id=asset_id)
	else:
		if user_perm != 0:		# 非普通用户
			asset_find = Asset.objects.all()		# 过滤所有资产信息
		else:		# 普通用户
			pass

	if idc_name:
		asset_find = asset_find.filter(idc__name__contains=idc_name)		# 过滤满足条件的idc资产记录

	if group_name:
		asset_find = asset_find.filter(group__name__contains=group_name)		# 过滤满足条件的group_name资产记录

	if asset_type:
		asset_find = asset_find.filter(asset_type__contains=asset_type)		# 过滤满足条件的asset_type资产记录

	if status:
		asset_find = asset_find.filter(status__contains=status)		# 过滤满足条件的status资产记录

	if keyword:
		asset_find = asset_find.filter(
			Q(hostname__contains=keyword) |
			Q(other_ip__contains=keyword) |
			Q(ip__contains=keyword) |
			Q(remote_ip__contains=keyword) |
			Q(comment__contains=keyword) |
			Q(username__contains=keyword) |
			# Q(group__name__contains=keyword) |		# 这个过滤条件会导致过滤结果重复
			Q(cpu__contains=keyword) |
			Q(memory__contains=keyword) |
			Q(disk__contains=keyword) |
			Q(brand__contains=keyword) |
			Q(cabinet__contains=keyword) |
			Q(sn__contains=keyword) |
			Q(system_type__contains=keyword) |
			Q(system_version__contains=keyword)
		)

	if export:
		pass

	assets_list, p, assets, page_range, current_page, show_first, show_end = pages(asset_find, request)
	if user_perm != 0:
		return my_render('jasset/asset_list.html', locals(), request)
	else:
		return my_render('jasset/asset_cu_list.html', locals(), request)


@require_role('admin')
def idc_list(request):
	'''
	IDC视图
	'''
	header_title, path1, path2 = u'查看IDC', u'资产管理', u'查看IDC'
	posts = IDC.objects.all()
	keyword = request.GET.get('keyword', '')
	if keyword:
		posts = IDC.objects.filter(Q(name__icontains=keyword) | Q(comment__icontains=keyword))		# 过滤IDC名称或者备注包含关键字的记录
	else:
		posts = IDC.objects.exclude(name='ALL').order_by('id')		# 过滤IDC name不为ALL的记录, 依据ID号排序

	contact_list, p, contacts, page_range, current_page, show_first, show_end = pages(posts, request)

	return my_render('jasset/idc_list.html', locals(), request)


@require_role('admin')
def idc_add(request):
	'''
	IDC增加视图
	'''
	header_title, path1, path2 = u'添加IDC', u'资产管理', u'添加IDC'
	if request.method == 'POST':
		idc_form = IdcForm(request.POST)
		if idc_form.is_valid():		# 判断提交过来的数据是否有效
			idc_name = idc_form.cleaned_data['name']		# 数据验证通过, 所提交的数据保存在一个cleaned_data字典中
			if IDC.objects.filter(name=idc_name):		# 机房名称必须唯一
				emg = u'添加失败, IDC名称 %s 已经存在' % (idc_name, )
				return my_render('jasset/idc_add.html', locals(), request)
			else:
				idc_form.save()		# 在jasset_idc表中添加记录
				msg = u'IDC: %s添加成功' % (idc_name, )
				return HttpResponseRedirect(reverse('idc_list'))
		else:
			emg = u'表单数据验证不通过, 请重新提交'
	else:
		idc_form = IdcForm()

	return my_render('jasset/idc_add.html', locals(), request)


@require_role('admin')
def idc_edit(request):
	'''
	编辑IDC记录视图
	'''
	header_title, path1, path2 = u'编辑IDC', u'资产管理', u'编辑IDC'
	idc_id = request.GET.get('id', '')
	idc = get_object(IDC, id=idc_id)
	if request.method == 'POST':
		idc_name = request.POST.get('name', '')
		if idc.name != idc_name:		# 增加机房名重名判断
			if IDC.objects.filter(name=idc_name):
				emg = u'IDC名称已经存在'
				idc_form = IdcForm(instance=idc)
				return my_render('jasset/idc_edit.html', locals(), request)

		idc_form = IdcForm(request.POST, instance=idc)		# 指定IDC instance, 后续修改都作用于该instance
		if idc_form.is_valid():
			idc_form.save()
			return HttpResponseRedirect(reverse('idc_list'))
		else:
			emg = u'IDC编辑失败'
	else:
		if idc:
			idc_form = IdcForm(instance=idc)		# 指定一个IDC instance
		else:
			return HttpResponseRedirect(reverse('idc_list'))

	return my_render('jasset/idc_edit.html', locals(), request)


@require_role('admin')
def idc_del(request):
	'''
	单个删除, 或批量删除IDC记录视图
	'''
	idc_ids = request.GET.get('id', '')
	idc_id_list = idc_ids.split(',')

	for idc_id in idc_id_list:
		idc = IDC.objects.filter(id=idc_id)
		if idc:
			idc.delete()

	return HttpResponseRedirect(reverse('idc_list'))



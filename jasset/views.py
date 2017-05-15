#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django.shortcuts import render
from mysite.api import *
from django.db.models import Q
from jasset.models import AssetGroup, Asset, IDC, ASSET_TYPE, ASSET_STATUS
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
	asset_all = Asset.objects.all()

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
			smg = u'主机组 %s 添加成功' % (name, )

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
			group.asset_set.clear()		# 清除资产组中的所有主机
			db_update_group(id=group_id, name=name, comment=comment, asset_select=asset_select)
			smg = u'主机组 %s 编辑成功' % (name, )

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
	default_port = default_setting.field2 if default_setting else ''
	if request.method == 'POST':
		af_post = AssetForm(request.POST)		# 创建一个AssetForm 实列
		hostname = request.POST.get('hostname', '')
		ip = request.POST.get('ip', '')
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
			if af_post.is_valid():
				asset_save = af_post.save(commit=False)		# commit=False, 避免Model实列立即存储到数据库
				if not use_default_auth:
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
				msg = u'主机 %s 添加失败' % (hostname, )
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
	log = Log.objects.filter(host=asset.hostname)
	if perm_info:
		user_perm = []
		for perm, value in perm_info.items():
			if perm == 'user':
				for user, role_dic in value.items():
					user_perm.append([user, role_dic.get('role', '')])
			elif perm == 'user_group' or perm == 'rule':
				user_group_perm = value

	asset_record = AssetRecord.objects.filter(asset=asset).order_by('-alert_time')

	return my_render('jasset/asset_detail.html', locals(), request)


def asset_update(request):
	pass


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
		password_old = asset.password		# 保留旧password
	af = AssetForm(instance=asset)		# 校验表单数据,指定了instance实列, 后续所有修改都做用在这个实列(asset)上
	if request.method == 'POST':
		pass

	return my_render('jasset/asset_edit.html', locals(), request)


def asset_del(request):
	pass


def asset_edit_batch(request):
	pass


def asset_update_batch(request):
	pass


def asset_add_batch(request):
	pass


@require_role('user')
def asset_list(request):
	'''
	主机资产视图
	'''
	header_title, path1, path2 = u'查看资产', u'资产管理', u'查看资产'
	username = request.user.username
	user_perm = request.session['role_id']		# 用户权限, 2: SU, 1: GA, 0: CU
	idc_all = IDC.objects.filter()		# 过滤所有的IDC信息
	asset_group_all = AssetGroup.objects.all()		# 过滤所有的资产组信息
	asset_types = ASSET_TYPE		# 资产类型, 定义7种资产类型
	asset_status = ASSET_STATUS		# 资产状态, 三种状态: 已上线, 未上线, 已下架
	idc_name = request.GET.get('idc', '')		# 从表单里面提交
	group_name = request.GET.get('group', '')		# 从表单里面提交
	asset_type = request.GET.get('asset_type', '')		# 从表单提交
	status = request.GET.get('status', '')		# 从表单提交
	keyword = request.GET.get('keyword', '')		# 从表单提交
	export = request.GET.get('export', False)
	group_id = request.GET.get('group_id', '')		# 在资产组中, 每一个资产组所关联的资产, 由group_id查询参数连接
	idc_id = request.GET.get('idc_id', '')		# 在IDC中, 每一个IDC所关联的资产, 由idc_id查询参数连接
	asset_id_all = request.GET.getlist('id', '')		# 获取所提交的所有资产

	if group_id:
		pass
	elif idc_id:
		pass
	else:
		if user_perm != 0:		# 非普通用户
			asset_find = Asset.objects.all()		# 过滤所有资产信息
		else:
			pass

	if idc_name:
		pass

	if group_name:
		pass

	if asset_type:
		pass

	if status:
		pass

	if keyword:
		pass

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
	header_title, path1, path2 = '添加IDC', '资产管理', '添加IDC'
	if request.method == 'POST':
		idc_form = IdcForm(request.POST)
		if idc_form.is_valid():		# 判断提交过来的数据是否有效
			idc_name = idc_form.cleaned_data['name']		# 数据验证通过, 所提交的数据保存在一个cleaned_data字典中
			if IDC.objects.filter(name=idc_name):		# 机房名称必须唯一
				emg = u'添加失败, IDC名称 %s 已经存在' % (idc_name, )
				return my_render('jasset/idc_add.html', locals(), request)
			else:
				idc_form.save()		# 在jasset_idc表中添加记录
				smg = u'IDC: %s添加成功' % (idc_name, )
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

		idc_form = IdcForm(request.POST, instance=idc)
		if idc_form.is_valid():
			idc_form.save()
			return HttpResponseRedirect(reverse('idc_list'))
		else:
			emg = u'IDC编辑失败'
	else:
		if idc:
			idc_form = IdcForm(instance=idc)
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
		if idc_id:
			IDC.objects.filter(id=idc_id).delete()

	return HttpResponseRedirect(reverse('idc_list'))


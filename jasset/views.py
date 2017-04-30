#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django.shortcuts import render
from mysite.api import *
from django.db.models import Q
from jasset.models import AssetGroup, Asset, IDC
from jasset.asset_api import *
from jasset.forms import IdcForm
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


def asset_list(request):
	pass


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
		idc_form = IdcForm(request.POST, instance=idc)
		if idc_form.is_valid():
			idc_form.save()
			return HttpResponseRedirect(reverse('idc_list'))
		else:
			emg = u'IDC编辑失败'
	else:
		idc_form = IdcForm(instance=idc)

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


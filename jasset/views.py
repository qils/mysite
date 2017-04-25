#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django.shortcuts import render
from mysite.api import *
from django.db.models import Q
from jasset.models import AssetGroup, Asset
from jasset.asset_api import *
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


def asset_list(request):
	pass


def idc_list(request):
	pass


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
	header_title, path1, path2 = u'编辑主机组', u'资产管理', u'编辑主机组'
	group_id = request.GET.get('id', '')
	group = get_object(AssetGroup, id=group_id)

	asset_all = Asset.objects.all()		# 筛选所有主机
	asset_select = Asset.objects.filter(group=group)		# 筛选添加到资产组中的主机
	asset_no_select = [a for a in asset_all if a not in asset_select]

	if request.method == 'POST':
		pass

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



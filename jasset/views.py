#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django.shortcuts import render
from mysite.api import *
from django.db.models import Q
from jasset.models import AssetGroup, Asset
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
		pass

	return my_render('jasset/group_add.html', locals(), request)


def group_edit(request):
	pass


def group_del(request):
	pass



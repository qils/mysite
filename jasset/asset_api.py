#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from mysite.api import *


def group_add_asset(asset_group, asset_id=None, asset_ip=None):
	'''
	资产添加到资产组
	'''
	if asset_id:
		asset = get_object(Asset, id=asset_id)
	else:
		asset = get_object(Asset, ip=asset_ip)

	if asset:
		asset_group.asset_set.add(asset)		# 添加资产到关联的资产组


def db_add_group(**kwargs):
	'''
	往数据库中添加资产组记录
	'''
	name = kwargs.get('name', '')
	asset_group = get_object(AssetGroup, name=name)
	asset_id_list = kwargs.pop('asset_select')

	if not asset_group:
		asset_group = AssetGroup(**kwargs)
		asset_group.save()
		for asset_id in asset_id_list:
			group_add_asset(asset_group, asset_id)		# 往资产组中添加资产
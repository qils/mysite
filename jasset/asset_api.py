#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import xlrd
from mysite.api import *
from jasset.models import ASSET_STATUS, ASSET_TYPE, ASSET_ENV


def excel_to_db(excel_file):
	'''
	读取excel文件内容, 保存内容到资产表
	'''
	try:
		data = xlrd.open_workbook(filename=None, file_contents=excel_file.read())		# 读取excel文件数据
	except Exception, e:
		return False
	else:
		table = data.sheets()[0]		# 通过索引顺序获取工作表
		rows = table.nrows		# 获取总行数
		for row_num in range(1, rows):
			row = table.row_values(row_num)		# 获取某一行的内容
			if row:
				group_instance = []
				ip, port, hostname, use_default_auth, username, password, group = row
				if get_object(Asset, hostname=hostname):		# 是否有重复的主机
					continue
				if isinstance(password, int) or isinstance(password, float):
					password = unicode(int(password))
				use_default_auth = 1 if use_default_auth == u'默认' else 0
				password_encode = CRYPTOR.encrypt(password)
				if hostname:
					logger.debug('---> here')
					asset = Asset(
						ip=ip,
						port=port,
						hostname=hostname,
						use_default_auth=use_default_auth,
						username=username,
						password=password_encode
					)
					asset.save()
					group_list = group.split('/')		# 添加的主机组必须按/分隔
					for group_name in group_list:
						group = get_object(AssetGroup, name=group_name)
						if group:		# 检查输入的主机组是否存在
							group_instance.append(group)
						else:
							continue
					asset.group = group_instance
					asset.save()
		return True


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


def db_update_group(**kwargs):
	'''
	更新资产组数据表
	'''
	group_id = kwargs.pop('id')
	asset_id_list = kwargs.pop('asset_select')
	asset_group = get_object(AssetGroup, id=group_id)

	for asset_id in asset_id_list:
		group_add_asset(asset_group, asset_id)		# 重新将资产主机添加到资产组

	AssetGroup.objects.filter(id=group_id).update(**kwargs)


def asset_diff(before, after):
	'''
	资产主机信息更新前, 后的数据对比, 返回前后不一致的数据字段
	'''
	alter_dic = {}
	before_dic, after_dic = before, dict(after.iterlists())		# before为更新前资产信息字段字典, after_dic是通过request.POST提交的更新后的列表组成的字典

	for k, v in before_dic.items():
		after_dic_values = after_dic.get(k, [])
		if k == 'group':		# 多对多字段比较
			after_dic_value = after_dic_values if len(after_dic_values) > 0 else []
			uv = v if v is not None else []		# 这里由空unicode字符变成了空列表
		else:		# 其他字段比较
			after_dic_value = after_dic_values[0] if len(after_dic_values) > 0 else u''
			uv = unicode(v) if v is not None else u''
		if uv != after_dic_value:
			alter_dic.update({k: [uv, after_dic_value]})		# 保留前后的信息

	for k, v in alter_dic.items():
		if v == [None, u'']:		# 前面for循环已经判断了v值不为None
			alter_dic.pop(k)

	return alter_dic


def get_tuple_name(asset_tuple, value):
	for t in asset_tuple:
		if t[0] == value:
			return t[1]
	return ''


def get_tuple_diff(asset_tuple, field_name, value):
	old_name = get_tuple_name(asset_tuple, int(value[0])) if value[0] else u''
	new_name = get_tuple_name(asset_tuple, int(value[1])) if value[1] else u''
	alert_info = [field_name, old_name, new_name]
	return alert_info


def db_asset_alert(asset, username, alert_dic, username_old=None):
	'''
	将资产变更信息记录到AssetRecord表
	'''
	alert_list = []
	asset_tuple_dic = {'status': ASSET_STATUS, 'env': ASSET_ENV, 'asset_type': ASSET_TYPE}
	for field, value in alert_dic.iteritems():
		field_name = Asset._meta.get_field_by_name(field)[0].verbose_name		# 获取每个字段的verbose_name
		if field == 'idc':		# 判断变更的是否为idc字段
			old = IDC.objects.filter(id=value[0]) if value[0] else u''
			new = IDC.objects.filter(id=value[1]) if value[1] else u''
			old_name = old[0].name if old else u''
			new_name = new[0].name if new else u''
			alert_info = [field_name, old_name, new_name]
		elif field in ['status', 'env', 'asset_type']:
			alert_info = get_tuple_diff(asset_tuple_dic.get(field), field_name, value)
		elif field == 'group':		# 判断变更为group字段
			old, new = [], []
			for group_id in value[0]:
				group_name = AssetGroup.objects.get(id=int(group_id)).name
				old.append(group_name)
			for group_id in value[1]:
				group_name = AssetGroup.objects.get(id=int(group_id)).name
				new.append(group_name)
			if sorted(old) == sorted(new):
				continue
			else:
				alert_info = [field_name, '|'.join(old), '|'.join(new)]
		elif field == 'use_default_auth':
			if unicode(value[0]) == 'True' and unicode(value[1]) == 'on' or unicode(value[0]) == 'False' and unicode(value[1]) == '':
				continue		# 以上条件满足,则use_default_auth字段没有变更
			else:
				name = asset.username		# 默认账号
				alert_info = [field_name, '默认', name] if unicode(value[0]) == 'True' else [field_name, username_old, '默认']
		elif field in ['username', 'password']:		# 如果变更的为用户名, 或者密码字段则不记录变更信息
			continue
		elif field == 'is_active':
			if unicode(value[0]) == 'True' and unicode(value[1]) == '1' or unicode(value[0]) == 'False' and unicode(value[1]) == '0':
				continue		# 满足以上条件, 则is_active字段没有变更
			else:
				alert_info = [field_name, '激活', '禁用'] if unicode(value[0]) == 'True' else [field_name, '禁用', '激活']
		else:
			alert_info = [field_name, unicode(value[0]), unicode(value[1])]

		if 'alert_info' in dir():		# dir() 返回当前空间的变量
			alert_list.append(alert_info)
	if alert_list:
		AssetRecord.objects.create(
			asset=asset,
			username=username,
			content=alert_list			# 变更内容字段
		)

#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from mysite.api import *
from mysite.models import Setting
from django.db.models.query import QuerySet
from jperm.models import PermRole, PermPush, PermRule, PermSudo, PermLog


def get_group_user_perm(ob):
	'''
	ob是用户或者用户组对象,
	获取用户, 用户组授权的资产, 资产组
	'''
	perm = {}
	if isinstance(ob, User):
		rule_all = set(PermRule.objects.filter(user=ob))		# 过滤某个用户对象关联的授权规则
		for user_group in ob.group.all():			# 获取该用户对象所加入的用户组
			rule_all = rule_all.union(set(PermRule.objects.filter(user_group=user_group)))		# 过滤某个用户组对象的授权规则
	elif isinstance(ob, UserGroup):
		rule_all = PermRule.objects.filter(user_group=ob)
	else:
		rule_all = []

	perm['rule'] = rule_all		# 所有的授权规则
	perm_asset_group = perm['asset_group'] = {}
	perm_asset = perm['asset'] = {}
	perm_role = perm['role'] = {}
	for rule in rule_all:
		asset_groups = rule.asset_group.all()		# 获取授权规则关联的所有资产组
		assets = rule.asset.all()		# 获取授权规则关联的所有资产
		perm_roles = rule.role.all()		# 获取授权规则关联的系统用户
		group_assets = []		# 一条规则关联的所有资产组中的所有资产
		for asset_group in asset_groups:
			group_assets.extend(asset_group.asset_set.all())		# 过滤一个资产组所关联的所有资产

		calc_asset = set(assets).union(set(group_assets))		# 合并一个授权规则关联的所有资产

		# 获取一个规则授权的系统用户所对应的资产, 资产组
		for role in perm_roles:
			if perm_role.get(role):
				perm_role[role]['asset'] = perm_role[role].get('asset', set()).union(calc_asset)
				perm_role[role]['asset_group'] = perm_role[role].get('asset_group', set()).union(set(asset_groups))
			else:
				perm_role[role] = {'asset': calc_asset, 'asset_group': set(asset_groups)}

		# 获取一个规则用户授权的资产
		for asset in assets:
			if perm_asset.get(asset):
				perm_asset[asset].get('role', set()).update(set(perm_roles))
				perm_asset[asset].get('rule', set()).add(rule)
			else:
				perm_asset[asset] = {'role': set(perm_roles), 'rule': set([rule])}

		# 获取一个规则用户授权的资产组
		for asset_group in asset_groups:
			asset_group_assets = asset_group.asset_set.all()		# 获取一个资产组所有关联的资产
			if perm_asset_group.get(asset_group):
				perm_asset_group[asset_group].get('role', set()).update(set(perm_roles))
				perm_asset_group[asset_group].get('rule', set()).add(rule)
			else:
				perm_asset_group[asset_group] = {
					'role': set(perm_roles),
					'rule': set([rule]),
					'asset': asset_group_assets
				}

			# 将资产组中的资产添加到资产授权中
			for asset in asset_group_assets:
				if perm_asset.get(asset):
					perm_asset[asset].get('role', set()).update(perm_asset_group[asset_group].get('role', set()))
					perm_asset[asset].get('rule', set()).update(perm_asset_group[asset_group].get('rule', set()))
				else:
					perm_asset[asset] = {
						'role': perm_asset_group[asset_group].get('role', set()),
						'rule': perm_asset_group[asset_group].get('rule', set())
					}
	return perm


def get_group_asset_perm(ob):
	'''
	ob为资产, 或者资产组,
	获取资产, 资产组授权的用户, 用户组
	'''
	perm = {}
	if isinstance(ob, Asset):
		rule_all = PermRule.objects.filter(asset=ob)
	elif isinstance(ob, AssetGroup):
		rule_all = PermRule.objects.filter(asset_group=ob)
	else:
		rule_all = []

	perm['rule'] = rule_all
	perm_user = perm['user'] = {}
	perm_user_group = perm['user_group'] = {}
	for rule in rule_all:
		users = rule.user.all()
		user_groups = rule.user_group.all()

		# 获取一个规则资产授权的用户
		for user in users:
			if perm_user.get(user):
				perm_user[user].get('role', set()).update(set(rule.role.all()))
				perm_user[user].get('rule', set()).add(rule)
			else:
				perm_user[user] = {'role': set(rule.role.all()), 'rule': set([rule])}

		# 获取一个规则资产授权的用户组
		for user_group in user_groups:
			user_group_users = user_group.user_set.all()		# 获取一个用户组中所有的用户
			if perm_user_group.get(user_group):
				perm_user_group[user_group].get('role', set()).update(set(rule.role.all()))
				perm_user_group[user_group].get('rule', set()).add(rule)
			else:
				perm_user_group[user_group] = {'role': set(rule.role.all()), 'rule': set([rule]), 'user': user_group_users}

			# 将用户组中的资产添加到用户授权中
			for user in user_group_users:
				if perm_user.get(user):
					perm_user[user].get('role', set()).update(perm_user_group[user_group].get('role', set()))		# 因为在perm_user_group, user_group['role']是一个集合, 所以这里不能用add函数
					perm_user[user].get('rule', set()).update(perm_user_group[user_group].get('rule', set()))		# 解释同上
				else:
					perm_user[user] = {'role': perm_user_group[user_group].get('role', set()), 'rule': perm_user_group[user_group].get('rule', set())}

	return perm


def gen_resource(ob, perm=None):
	'''
	ob为用户或资产列表或Queryset, 如果同时输入用户和{'role': role1, 'asset': []}，则获取用户在这些资产上的信息,生成MyInventory需要的resource文件
	'''
	res = []
	if isinstance(ob, dict):
		pass
	elif isinstance(ob, User):
		pass
	elif isinstance(ob, (list, QuerySet)):
		for asset in ob:
			info = get_asset_info(asset)		# 获取每个资产的信息, 将信息保存在字典对象中
			res.append(info)		# res 为每个资产信息字典组成的列表

	return res


def get_role_info(role_id, query_type='all'):
	'''
	返回一个授权系统用户关联信息
	'''
	role_obj = PermRole.objects.get(id=role_id)		# 获取授权用户对象
	perm_rule_obj = role_obj.perm_rule.all()		# PermRule模型中定义related_name参数为perm_rule,在关联的多对多模型中可以使用
	users_obj = []
	user_groups_obj = []
	assets_obj = []
	asset_groups_obj = []
	for perm_rule in perm_rule_obj:		# 遍历授权规则, 和源码遍历方式不同
		users_obj.extend(perm_rule.user.all())		# 授权规则关联的所有User
		user_groups_obj.extend(perm_rule.user_group.all())		# 授权规则关联的所有UserGroup
		assets_obj.extend(perm_rule.asset.all())		# 授权规则关联的所有Asset
		asset_groups_obj.extend(perm_rule.asset_group.all())		# 授权规则关联的所有AssetGroup

	if query_type == 'all':
		return {
			'rules': set(perm_rule_obj),
			'users': set(users_obj),
			'user_groups': set(user_groups_obj),
			'assets': set(assets_obj),
			'asset_groups': set(asset_groups_obj)
		}
	elif query_type == 'rule':
		return {'rules': set(perm_rule_obj)}
	elif query_type == 'user':
		return {'users': set(users_obj)}
	elif query_type == 'user_group':
		return {'user_groups': set(user_groups_obj)}
	elif query_type == 'asset':
		return {'assets': set(assets_obj)}
	elif query_type == 'asset_group':
		return {'asset_groups': set(asset_groups_obj)}
	else:
		return u'不支持的查询'


def get_role_push_host(role):
	'''
	获取系统用户推送信息
	'''
	pushs = PermPush.objects.filter(role=role)		# 获取某个系统用户所有的推送记录
	all_assets = Asset.objects.all()		# 过滤所有的资产信息
	asset_pushed = {}		# 用来保存某个系统用户推送的资产
	for push in pushs:
		asset_pushed[push.asset] = {
			'success': push.success,
			'key': push.is_public_key,
			'password': push.is_password,
			'result': push.result
		}
	no_push_assets = set(all_assets) - set(asset_pushed.keys())
	return asset_pushed, no_push_assets


def user_have_perm(user, asset):
	user_perm_all = get_group_user_perm(user)		# 获取授权用户所有的授权信息
	user_perm_assets = user_perm_all.get('asset').keys()
	if asset in user_perm_assets:		# 如果需要连接的资产属于授权用户的授权资产, 返回资产授权的系统用户
		return user_perm_all.get('asset').get(asset).get('role')		# 返回资产关联的系统用户
	else:
		return []


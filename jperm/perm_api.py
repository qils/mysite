#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from mysite.api import *
from jperm.models import PermRole, PermPush, PermRule


def get_group_user_perm(ob):
	'''
	ob是用户或者用户组对象,
	获取用户, 用户组授权的资产, 资产组
	'''
	perm = {}
	if isinstance(ob, User):
		rule_all = set(PermRule.objects.filter(user=ob))		# 过滤某个用户对象的授权规则
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
		perm_roles = rule.role.all()		# 获取授权规则关联的授权角色
		group_assets = []		# 一条规则关联的所有资产组中的所有资产
		for asset_group in asset_groups:
			group_assets.extend(asset_group.asset_set.all())		# 过滤一个资产组所关联的所有资产

		# 获取一个规则授权的角色所对应的资产, 资产组
		for role in perm_roles:
			if perm_role.get(role):
				perm_role[role]['asset'] = perm_role[role].get('asset', set()).union(set(assets).union(set(group_assets)))
				perm_role[role]['asset_group'] = perm_role[role].get('asset_group', set()).union(set(asset_groups))
			else:
				perm_role[role] = {'asset': set(assets).union(set(group_assets)), 'asset_group': set(asset_groups)}

		# 获取一个规则用户授权的资产
		for asset in assets:
			if perm_asset.get(asset):
				perm_asset[asset].get('role', set()).update(set(rule.role.all()))
				perm_asset[asset].get('rule', set()).add(rule)
			else:
				perm_asset[asset] = {'role': set(rule.role.all()), 'rule': set([rule])}

		# 获取一个规则用户授权的资产组
		for asset_group in asset_groups:
			asset_group_assets = asset_group.asset_set.all()		# 获取一个资产组所有关联的资产
			if perm_asset_group.get(asset_group):
				perm_asset_group[asset_group].get('role', set()).update(set(rule.role.all()))
				perm_asset_group[asset_group].get('rule', set()).add(rule)
			else:
				perm_asset_group[asset_group] = {
					'role': set(rule.role.all()),
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

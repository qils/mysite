#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from __future__ import unicode_literals

import re
import os
from jperm.perm_api import *
from django.db.models import Q
from jperm.utils import trans_all, gen_keys
from mysite.models import Setting
from django.shortcuts import render
from jperm.ansible_api import MyTask
# Create your views here.


@require_role('admin')
def perm_sudo_list(request):
	'''
	sudo 列表视图
	'''
	header_title, path1, path2 = u'Sudo命令', u'别名管理', u'查看别名'
	sudos_list = PermSudo.objects.all()		# 获取所有sudo命令别名

	keyword = request.GET.get('search', '')
	if keyword:
		sudos_list = sudos_list.filter(Q(name=keyword))

	sudos_list, p, sudos, page_range, current_page, show_first, show_end = pages(sudos_list, request)

	return my_render('jperm/perm_sudo_list.html', locals(), request)


@require_role('admin')
def perm_sudo_add(request):
	'''
	添加sudo命令别名视图
	'''
	header_title, path1, path2 = u'Sudo命令', u'别名管理', u'添加别名'
	try:
		if request.method == 'POST':
			name = request.POST.get('sudo_name', '').strip().upper()
			comment = request.POST.get('sudo_comment', '').strip()
			commands = request.POST.get('sudo_commands', '').strip()

			if not name or not commands:
				raise ServerError(u'sudo name 和 commands是必填项!!!')

			deal_space_commands = [sub_command.strip() for sub_command in list_drop_str(re.split(r'[\n,\r]', commands), u'')]		# 处理为空的命令, 直接删除空
			deal_all_commands = map(trans_all, deal_space_commands)		# 处理字符为all的命令, 转换为大写
			commands = ', '.join(deal_all_commands)
			logger.debug(u'添加sudo %s: %s' % (name, commands))
			if get_object(PermSudo, name=name):		# 别名重复判断
				error = u'Sudo别名 %s 已经存在' % (name, )
			else:
				sudo = PermSudo(name=name, comment=comment, commands=commands)
				sudo.save()		# 存储到数据库
				msg = u'添加Sudo命令别名: %s 成功' % (name, )
	except ServerError, e:
		error = e

	return my_render('jperm/perm_sudo_add.html', locals(), request)


@require_role('admin')
def perm_sudo_edit(request):
	'''
	sudo别名编辑视图
	'''
	header_title, path1, path2 = u'Sudo命令', u'别名管理', u'编辑别名'
	sudo_id = request.GET.get('id', '')
	sudo = PermSudo.objects.get(id=sudo_id)		# 获取当前sudo对象
	if sudo:
		try:
			if request.method == 'POST':
				name = request.POST.get('sudo_name', '').strip().upper()
				test_sudo = get_object(PermSudo, name=name)
				if test_sudo and test_sudo.id != sudo.id:		# 源码中没有对编辑后的name是否重名做判断, 在模型中有指定name字段唯一, 在这里没有判断的话会触发模型中的异常
					raise ServerError(u'别名重名')
				comment = request.POST.get('sudo_comment', '')
				commands = request.POST.get('sudo_commands', '')

				if not name or not commands:
					raise ServerError('sudo name 和 commands是必填项!!!')

				deal_space_commands = [sub_command.strip() for sub_command in list_drop_str(re.split(r'[\n,\r]', commands), u'')]
				deal_all_commands = map(trans_all, deal_space_commands)		# 处理字符为all的命令, 转换为大写
				commands = ', '.join(deal_all_commands)
				logger.debug(u'添加sudo %s: %s' % (name, commands))

				sudo.name = name
				sudo.commands = commands
				sudo.comment = comment
				sudo.save()

				msg = u'更新命令别名 %s 成功' % (name, )
		except ServerError, e:
			error = e
		return my_render('jperm/perm_sudo_edit.html', locals(), request)
	else:
		return HttpResponseRedirect(reverse('sudo_list'))


@require_role('admin')
def perm_sudo_delete(request):
	'''
	删除某个sudo视图
	'''
	if request.method == 'POST':
		sudo_id = request.POST.get('id', '')
		sudo = get_object(PermSudo, id=sudo_id)
		if sudo:
			sudo_name = sudo.name
			sudo.delete()
			return HttpResponse(u'删除 %s 成功' % (sudo_name, ))
	else:
		return HttpResponse(u'不支持该操作')


@require_role('admin')
def perm_role_list(request):
	'''
	系统用户列表视图
	'''
	header_title, path1, path2 = u'系统用户', u'系统用户管理', u'查看系统用户'

	roles_list = PermRole.objects.all()		# 获取所有系统角色
	role_id = request.GET.get('id', '')
	keyword = request.GET.get('search', '')

	if keyword:
		roles_list = roles_list.filter(Q(name=keyword))

	if role_id:
		roles_list = roles_list.filter(id=role_id)

	roles_list, p, roles, page_range, current_page, show_first, show_end = pages(roles_list, request)

	return my_render('jperm/perm_role_list.html', locals(), request)


@require_role('admin')
def perm_role_add(request):
	'''
	增加系统角色视图
	'''
	header_title, path1, path2 = u'系统用户', u'系统用户管理', u'添加系统用户'
	sudos = PermSudo.objects.all()

	if request.method == 'POST':
		name = request.POST.get('role_name', '').strip()		# 获取系统用户名称
		password = request.POST.get('role_password', '')		# 获取密码
		key_content = request.POST.get('role_key', '')		# 获取提交的私钥
		comment = request.POST.get('role_comment', '')
		sudo_ids = request.POST.getlist('sudo_name', [])		# 获取关联的sudo

		try:
			if get_object(PermRole, name=name):
				raise ServerError(u'该系统用户 %s 已经存在' % (name, ))		# 系统用户名重名检查
			if name == 'root':
				raise ServerError(u'禁止使用root用户作为系统用户')
			default = get_object(Setting, name='default')		# 暂时没用到
			if len(password) > 64:
				raise ServerError(u'密码长度不能超过64位')

			if password:
				encrypt_pass = CRYPTOR.encrypt(password)
			else:
				encrypt_pass = CRYPTOR.encrypt(CRYPTOR.gen_rand_key(20))		# 如果不输入密码字符, 将随机生成一个密码
			sudos_obj = [get_object(PermSudo, id=sudo_id) for sudo_id in sudo_ids]
			if key_content:
				try:
					key_path = gen_keys(key=key_content)		# 生成秘钥文件
				except SSHException, e:
					raise ServerError(e)
			else:
				key_path = gen_keys()
			role = PermRole(name=name, password=encrypt_pass, comment=comment, key_path=key_path)
			role.save()
			role.sudo = sudos_obj
			role.save()		# 增加这行, 源码中不包括这行
			msg = u'添加系统用户: %s ' % (name, )
			return HttpResponseRedirect(reverse('role_list'))
		except ServerError, e:
			error = e

	return my_render('jperm/perm_role_add.html', locals(), request)


@require_role('admin')
def perm_role_edit(request):
	'''
	系统用户编辑视图
	'''
	role_id = request.GET.get('id', '')		# 获取的id为字符对象
	role = get_object(PermRole, id=role_id)		# 获取编辑的role对象
	sudo_all = PermSudo.objects.all()		# 获取所有sudo对象
	if role:
		role_sudos = role.sudo.all()		# 获取当前role所关联的sudo
		role_pass = CRYPTOR.decrypt(role.password)		# 对称解密存储在数据库中加密的密码, 数据库中保存的密码都是对称加密后存储的
		if request.method == 'GET':
			return my_render('jperm/perm_role_edit.html', locals(), request)
		elif request.method == 'POST':		# 获取post数据, 更新系统用户信息
			role_name = request.POST.get('role_name', '')
			role_password = request.POST.get('role_password', '')
			role_comment = request.POST.get('comment', '')
			key_content = request.POST.get('role_key', '')
			sudo_name = request.POST.getlist('sudo_name', [])
			role_sudos = [PermSudo.objects.get(id=sudo_id) for sudo_id in sudo_name]

			try:
				test_role = get_object(PermRole, name=role_name)		# 系统用户名称重名检查
				if test_role and role.id != test_role.id:
					raise ServerError(u'系统用户名称重名')

				if len(role_password) > 64:
					raise ServerError(u'密码长度过长')

				if role_name == 'root':
					raise ServerError(u'禁止使用root用户作为系统用户!!!')

				if role_password and role_password != role_pass:		# 密码变更才会重新计算新的密码
					encrypt_pass = CRYPTOR.encrypt(role_password)
					role.password = encrypt_pass

				if key_content:		# 私钥变更时, 才做更新
					try:
						key_path = gen_keys(key=key_content, key_path_dir=role.key_path)
					except SSHException, e:
						raise ServerError(u'输入的私钥不合法')

				role.name = role_name
				role_comment = role_comment
				role.sudo = role_sudos		# 直接更新sudo
				role.save()
				msg = u'更新系统用户 %s 完成' % (role.name, )
			except ServerError, e:
				error = e
			return my_render('jperm/perm_role_edit.html', locals(), request)

	return HttpResponseRedirect(reverse('role_list'))
	

@require_role('admin')
def perm_role_push(request):
	'''
	推送系统用户视图
	'''
	header_title, path1, path2 = u'系统用户', u'系统用户管理', u'系统用户推送'
	role_id = request.GET.get('id', '')
	asset_ids = request.GET.get('asset_id', '')
	role = get_object(PermRole, id=role_id)
	assets = Asset.objects.all()		# 所有主机资产
	asset_groups = AssetGroup.objects.all()		# 所有资产组

	if asset_ids:
		need_push_asset = [get_object(Asset, id=asset_id) for asset_id in asset_ids.split(',')]

	if request.method == 'POST':
		# 获取推送角色的名称列表
		# 计算出需要推送的资产列表
		assets_ids = request.POST.getlist('assets', [])		# 获取推送的资产id列表
		asset_groups_ids = request.POST.getlist('asset_groups', [])		# 获取推送的资产组id列表
		assets_obj = [Asset.objects.get(id=asset_id) for asset_id in assets_ids]		# 计算推送的资产
		asset_groups_obj = [AssetGroup.objects.get(id=group_id) for group_id in asset_groups_ids]
		group_assets_obj = []
		for group_asset in asset_groups_obj:
			group_assets_obj.extend(group_asset.asset_set.all())		# 计算所有组对象中的资产
		calc_assets = list(set(assets_obj) | set(group_assets_obj))		# 去重合并所有资产

		push_resource = gen_resource(calc_assets)

		# 调用Ansible API进行推送
		password_push = True if request.POST.get('use_password', '') else False		# 密码推送, 目前源码里不在支持推送密码
		key_push = True if request.POST.get('use_publicKey', '') else False		# 推送公钥
		task = MyTask(push_resource)		# 推送资源列表, 每个资源信息保存在字典对象中
		ret = {}

		# 通过秘钥方式推送角色
		if key_push:
			ret['pass_push'] = task.add_user(role.name)		# 推送系统用户名, 没有密码, 系统用户统一使用秘钥通信
			ret['key_push'] = task.push_key(role.name, os.path.join(role.key_path, 'id_rsa.pub'))		# 推送系统用户公钥

		# 推送sudo配置文件
		if key_push:
			sudo_list = set([sudo for sudo in role.sudo.all()])
			if sudo_list:
				ret['sudo'] = task.push_sudo_file([role], sudo_list)		# 推送脚本, 修改目标主机/etc/sudoers
			else:
				ret['sudo'] = task.recyle_cmd_alias(role.name)		# sudo_list为空,回收sudo命令

		logger.debug(u'推送role结果: %s' % (ret, ))
		success_asset = {}
		failed_asset = {}

		for push_type, result in ret.items():
			if result.get('failed'):
				for hostname, info in result.get('failed').items():
					if hostname in failed_asset.keys():
						failed_asset[hostname] += info
					else:
						failed_asset[hostname] = info
			# 这里写的与源代码不同
			if result.get('ok'):
				for hostname, info in result.get('ok').items():
					if hostname in failed_asset.keys():
						continue		# 不能同时出现在failed和ok这两种结果中, 只有一种结果
					if hostname in success_asset.keys():
						if str(info) in success_asset.get('hostname', ''):
							pass
						else:
							success_asset[hostname] += str(info)
					else:
						success_asset[hostname] = str(info)
		logger.debug(success_asset)
		logger.debug(failed_asset)

	return my_render('jperm/perm_role_push.html', locals(), request)


def perm_role_delete(request):
	pass


def perm_role_get(request):
	pass


@require_role('admin')
def perm_role_detail(request):
	'''
	系统用户详细信息视图
	'''



@require_role('admin')
def perm_rule_list(request):
	'''
	授权规则列表视图
	'''
	header_title, path1, path2 = u'授权规则', u'规则管理', u'查看规则'
	rules_list = PermRule.objects.all()		# 顾虑所有授权规则
	rule_id = request.GET.get('id', '')
	keyword = request.GET.get('search', '')

	if rule_id:
		rules_list = rules_list.filter(id=rule_id)		# 依据rule_id过滤满足条件的授权规则

	if keyword:
		rules_list = rules_list.filter(Q(name__icontains=keyword))		# 依据查询关键字keyword过滤授权规则

	rules_list, p, rules, page_range, current_page, show_first, show_end = pages(rules_list, request)

	return my_render('jperm/perm_rule_list.html', locals(), request)


def perm_rule_detail(request):
	pass


@require_role('admin')
def perm_rule_add(request):
	'''
	添加授权规则视图
	'''
	header_title, path1, path2 = u'授权规则', u'规则管理', u'添加规则'

	users = User.objects.all()		# 获取所有用户, 用于添加授权规则
	user_groups = UserGroup.objects.all()		# 获取所有用户组, 用于添加授权规则
	assets = Asset.objects.all()		# 获取所有资产, 用于添加授权规则
	asset_groups = AssetGroup.objects.all()		# 获取所有资产组, 用于添加授权规则
	roles = PermRole.objects.all()		# 获取所有授权角色, 用于添加授权规则

	if request.method == 'POST':
		pass

	return my_render('jperm/perm_rule_add.html', locals(), request)


def perm_rule_edit(request):
	pass


def perm_rule_delete(request):
	pass
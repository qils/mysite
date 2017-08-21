#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from __future__ import unicode_literals

import re
import os
import shutil
from jperm.perm_api import *
from django.db.models import Q
from jperm.utils import trans_all, gen_keys
from mysite.models import Setting
from django.shortcuts import render
from jperm.ansible_api import MyTask
from django.http import HttpResponseBadRequest, HttpResponseNotAllowed
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
			name = request.POST.get('sudo_name', '').strip().upper()		# 将别名转换为大写
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
		return HttpResponseNotAllowed(u'不支持该操作')


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
		password = request.POST.get('role_password', '')		# 获取系统用户密码
		key_content = request.POST.get('role_key', '')		# 获取提交的私钥
		comment = request.POST.get('role_comment', '')
		sudo_ids = request.POST.getlist('sudo_name', [])		# 获取关联的sudo

		try:
			if get_object(PermRole, name=name):
				raise ServerError(u'该系统用户 %s 已经存在' % (name, ))		# 系统用户名重名检查
			if name == 'root':		# 这里禁止root用户作为系统用户
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

			role = PermRole(name=name, password=encrypt_pass, comment=comment, key_path=key_path)		# 保存到数据库
			role.save()
			role.sudo = sudos_obj		# 关联所有sudo
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
						key_path = gen_keys(key=key_content, key_path_dir=role.key_path)		# 指定密钥存放目录
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
	推送系统用户视图, 主要实现将系统用户推送至主机
	'''
	header_title, path1, path2 = u'系统用户', u'系统用户管理', u'系统用户推送'
	role_id = request.GET.get('id', '')
	role = get_object(PermRole, id=role_id)

	asset_ids = request.GET.get('asset_id', '')		# 重新推送带过来的asset_id参数
	assets = Asset.objects.all()		# 所有主机资产
	asset_groups = AssetGroup.objects.all()		# 所有资产组

	if asset_ids:
		need_push_asset = [get_object(Asset, id=asset_id) for asset_id in set(asset_ids.split(','))]		# 增加set表示去除相同的id

	if request.method == 'POST':
		# 获取推送角色的名称列表
		# 计算出需要推送的资产列表
		asset_ids = request.POST.getlist('assets', [])		# 获取推送的资产id列表
		asset_groups_ids = request.POST.getlist('asset_groups', [])		# 获取推送的资产组id列表
		assets_obj = [Asset.objects.get(id=asset_id) for asset_id in asset_ids]		# 计算推送的资产
		asset_groups_obj = [AssetGroup.objects.get(id=group_id) for group_id in asset_groups_ids]
		group_assets_obj = []
		for group_asset in asset_groups_obj:
			group_assets_obj.extend(group_asset.asset_set.all())		# 计算所有组对象中的资产
		calc_assets = list(set(assets_obj) | set(group_assets_obj))		# 去重合并所有资产, cals_assets为需要推送的资产列表

		push_resource = gen_resource(calc_assets)		# 生成每个资产的{hostname, ip, username, password, port, ssh_key}

		# 调用Ansible API进行推送
		password_push = True if request.POST.get('use_password', '') else False		# 推送密码, 目前源码里不在支持推送密码
		key_push = True if request.POST.get('use_publicKey', '') else False		# 推送公钥
		task = MyTask(push_resource)		# 推送资源列表, 每个资源信息保存在字典对象中
		ret = {}		# 保存所有推送信息结果

		# 通过秘钥方式推送角色
		if key_push:
			ret['pass_push'] = task.add_user(role.name)		# 推送系统用户名, 没有密码, 系统用户统一使用密钥通信
			ret['key_push'] = task.push_key(role.name, os.path.join(role.key_path, 'id_rsa.pub'))		# 推送系统用户公钥

		# 推送sudo配置文件
		if key_push:
			sudo_list = set([sudo for sudo in role.sudo.all()])
			if sudo_list:
				ret['sudo'] = task.push_sudo_file([role], sudo_list)		# 推送脚本, 修改目标主机/etc/sudoers
			else:
				ret['sudo'] = task.recycle_cmd_alias(role.name)		# sudo_list为空,回收对应系统用户sudo命令

		logger.debug(u'推送role结果: %s' % (ret, ))
		success_asset = {}		# 推送成功的资产
		failed_asset = {}		# 推送失败的资产

		for push_type, result in ret.iteritems():
			if result.get('failed'):		# 先对推送失败的资产进行统计, 只有用户名, 公钥, sudo三者全部推送成功才算推送成功
				for hostname, info in result.get('failed').iteritems():
					if hostname in failed_asset.keys():
						if info not in failed_asset.get(hostname):		# 失败的原因不同, 将失败原因追加
							failed_asset[hostname] += info
					else:
						failed_asset[hostname] = info

		for push_type, result in ret.iteritems():
			if result.get('ok'):
				for hostname, info in result.get('ok').iteritems():
					if hostname in failed_asset.keys():		# 有推送失败的记录, 不记录在推送成功的字典中
						continue

					if hostname in success_asset.keys():
						if str(info) not in success_asset.get(hostname):
							success_asset[hostname] += str(info)
					else:
						success_asset[hostname] = str(info)

		# 将推送信息记录到PermPush 表
		for asset in calc_assets:
			if PermPush.objects.filter(role=role, asset=asset):		# 相同的系统用户, 资产已经存在时只对信息更改, 不创建新推送记录
				func = PermPush.objects.filter(role=role, asset=asset).update
			else:
				def func(**kwargs):
					PermPush(**kwargs).save()

			if failed_asset.get(asset.hostname):		# 记录推送主机失败信息
				func(role=role, asset=asset, is_public_key=key_push, is_password=password_push, success=False, result=failed_asset.get(asset.hostname))
			else:		# 源码里面没有将推送成功信息记录到result
				func(role=role, asset=asset, is_public_key=key_push, is_password=password_push, success=True, result=success_asset.get(asset.hostname))

		if not failed_asset:
			msg = u'系统用户 %s 推送成功 [ %s ]' % (role.name, '|'.join(success_asset.keys()))
		else:
			error = u'系统用户 %s 推送失败 [ %s ], 推送成功 [ %s ]' % (role.name, '|'.join(failed_asset.keys()), '|'.join(success_asset.keys()))

	return my_render('jperm/perm_role_push.html', locals(), request)


@require_role('user')
def perm_role_get(request):
	'''
	获取授权用户视图
	'''
	asset_id = request.GET.get('id', '')
	if asset_id:
		asset = get_object(Asset, id=asset_id)		# 获取ID对应的资产对象
		if asset:
			roles = user_have_perm(request.user, asset)		# 获取授权的系统用户
			return HttpResponse(','.join([role.name for role in roles]))
	else:
		roles = get_group_user_perm(request.user).get('role').keys()
		return HttpResponse(','.join([role.name for role in roles]))

	return HttpResponse('error')


@require_role(role='admin')
def perm_role_delete(request):
	'''
	删除一个资产系统用户视图
	'''
	if request.method == 'GET':
		try:
			role_id = request.GET.get('id', '')		# 通过参数获取需要删除的系统用户role_id
			role = get_object(PermRole, id=role_id)
			if not role:
				raise ServerError(u'role_id %s 没有数据记录' % (role_id, ))
			filter_type = request.GET.get('filter_type', '')
			if filter_type:
				if filter_type == 'recycle_assets':
					recycle_assets = [push.asset for push in role.perm_push.all() if push.success]		# 只对推送成功的资产回收系统用户
					recycle_assets_ip = ','.join([asset.ip for asset in recycle_assets])
					return HttpResponse(recycle_assets_ip)
				else:
					return HttpResponse('no such filter_type: %s' % (filter_type, ))
			else:
				return HttpResponse('filter_type: ?')
		except ServerError, e:
			return HttpResponse(e)

	if request.method == 'POST':
		try:
			role_id = request.POST.get('id', '')
			role = get_object(PermRole, id=role_id)
			if not role:
				raise ServerError(u'role_id %s 无数据记录' % (role_id, ))
			role_key = role.key_path		# 获取资产系统用户密钥存储目录

			try:
				recycle_assets = [push.asset for push in role.perm_push.all if push.success]		# 只对推送成功的资产删除系统用户
			except Exception:
				logger.debug('--->here')
				return HttpResponse('error')
			
			if recycle_assets:
				recycle_resource = gen_resource(recycle_assets)		# 生成资产信息
				task = MyTask(recycle_resource)
				try:
					msg_del_user = task.del_user(role.name)		# 调用ansible api 删除系统用户
					msg_del_sudo = task.del_user_sudo(role.name)		# 调用ansible api 删除sudo
				except Exception, e:
					raise ServerError(u'回收已推送的系统用户失败: %s' % (e, ))

				logger.info('delete role %s - execute delete user: %s' % (role.name, msg_del_user))
				logger.info('delete role %s - execute delete sudo: %s' % (role.name, msg_del_sudo))

			try:
				shutil.rmtree(role_key)		# 删除系统用户key目录
			except Exception, e:
				raise ServerError(u'删除系统用户key失败: %s' % (e, ))

			logger.info('delete role %s - delete role key directory: %s' % (role.name, role_key))
			role.delete()		# 从PermRole表中删除该Role记录
			return HttpResponse(u'删除系统用户: %s' % (role.name, ))
		except ServerError, e:
			return HttpResponseBadRequest(u'删除失败, 原因: %s' % (e, ))
	return HttpResponseNotAllowed(u'仅支持POST请求')


@require_role('admin')
def perm_role_detail(request):
	'''
	系统用户详细信息视图
	'''

	header_title1, path1, path2 = u'系统用户', u'系统用户管理', u'系统用户详情'

	try:
		role_id = request.GET.get('id', '')
		role = get_object(PermRole, id=role_id)
		if not role:
			raise ServerError(u'系统用户不存在')
		role_info = get_role_info(role_id)

		rules = role_info.get('rules', '')		# 获取关联的授权规则
		users = role_info.get('users', '')		# 获取关联的User
		user_groups = role_info.get('user_groups', '')		# 获取关联的UserGroup
		assets = role_info.get('assets', '')		# 获取关联的资产
		asset_groups = role_info.get('asset_groups', '')		# 获取关联的资产组
		pushed_asset, need_push_asset = get_role_push_host(role)		# 获取系统用户推送到资产的推送信息
	except ServerError, e:
		logger.warning(e)

	return my_render('jperm/perm_role_detail.html', locals(), request)


@require_role('admin')
def perm_role_recycle(request):
	'''
	将系统用户从选择的资产中回收
	'''
	role_id = request.GET.get('role_id', '')
	asset_ids = request.GET.get('asset_id', '').split(',')
	role = get_object(PermRole, id=role_id)

	if role:		# 仅对推送的资产进行回收
		assets = [get_object(Asset, id=asset_id) for asset_id in asset_ids]
		recycle_asset = []
		for asset in assets:
			if PermPush.objects.filter(role=role, asset=asset):		# 判断系统用户是否有推送到资产
				recycle_asset.append(asset)

		if recycle_asset:
			recycle_resource = gen_resource(recycle_asset)
			task = MyTask(recycle_resource)

			try:
				msg_del_user = task.del_user(role.name)
				msg_del_sudo = task.del_user_sudo(role.name)
				logger.info('recycle user msg: %s' % (msg_del_user, ))
				logger.info('recycle sudo msg: %s' % (msg_del_sudo, ))
			except Exception, e:
				logger.warning('Recycle Role failed: %s' % (e, ))
				raise ServerError(u'回收已推送的系统用户失败: %s' % (e, ))

			for asset in recycle_asset:
				PermPush.objects.filter(role=role, asset=asset).delete()		# 删除推送记录

			return HttpResponse(u'删除成功')

	return HttpResponse(u'删除失败')


@require_role('admin')
def perm_rule_list(request):
	'''
	授权规则列表视图
	'''
	header_title, path1, path2 = u'授权规则', u'规则管理', u'查看规则'
	rules_list = PermRule.objects.all()		# 过滤所有授权规则
	rule_id = request.GET.get('id', '')
	keyword = request.GET.get('search', '')

	if rule_id:
		rules_list = rules_list.filter(id=rule_id)		# 依据rule_id过滤满足条件的授权规则

	if keyword:
		rules_list = rules_list.filter(Q(name__icontains=keyword))		# 依据查询关键字keyword过滤授权规则

	rules_list, p, rules, page_range, current_page, show_first, show_end = pages(rules_list, request)

	return my_render('jperm/perm_rule_list.html', locals(), request)


@require_role('admin')
def perm_rule_detail(request):
	'''
	授权规则详细信息视图
	'''
	header_title, path1, path2 = u'授权规则', u'规则管理', u'规则详情'
	try:
		if request.method == 'GET':
			rule_id = request.GET.get('id', '')
			rule = get_object(PermRule, id=rule_id)
			if not rule:
				raise ServerError(u'查询的授权规则不存在')

			users = rule.user.all()		# 获取授权规则关联的所有User
			user_groups = rule.user_group.all()		# 获取授权规则关联的所有UserGroup
			assets = rule.asset.all()		# 获取授权规则关联的所有Asset
			asset_groups = rule.asset_group.all()		# 获取授权规则关联的所有AssetGroup
			roles_name = [role.name for role in rule.role.all()]		# 获取授权规则关联的所有PermRole

			# 渲染模板数据
			roles_name = '|'.join(roles_name)
	except ServerError, e:
		logger.warning(e)

	return my_render('jperm/perm_rule_detail.html', locals(), request)


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
		users_select = request.POST.getlist('user', [])		# 获取选中的User
		user_groups_select = request.POST.getlist('user_group', [])		# 获取选中的UserGroup
		assets_select = request.POST.getlist('asset', [])		# 获取选中的Asset
		asset_groups_select = request.POST.getlist('asset_group', [])		# 获取选中的AssetGroup
		roles_select = request.POST.getlist('role', [])		# 获取选中的系统用户
		rule_name = request.POST.get('name', '')		# 授权规则名
		rule_comment = request.POST.get('comment', '')		# 授权备注

		try:
			rule = get_object(PermRule, name=rule_name)
			if rule:		# 检验授权规则名是否相同
				raise ServerError(u'授权规则 %s 已存在' % (rule_name, ))

			if not rule_name or not roles_select:
				raise ServerError(u'系统用户名称和授权规则名称不能为空')

			# 获取需要授权的主机列表
			assets_obj = [Asset.objects.get(id=asset_id) for asset_id in assets_select]
			asset_groups_obj = [AssetGroup.objects.get(id=asset_group_id) for asset_group_id in asset_groups_select]
			group_assets_obj = []
			for asset_group in asset_groups_obj:
				group_assets_obj.extend(asset_group.asset_set.all())
			calc_assets = set(assets_obj) | set(group_assets_obj)		# 合并资产组中的资产

			# 获取需要授权的用户, 用户组
			users_obj = [User.objects.get(id=user_id) for user_id in users_select]
			user_groups_obj = [UserGroup.objects.get(id=user_group_id) for user_group_id in user_groups_select]

			# 获取需要授权的系统用户
			roles_obj = [PermRole.objects.get(id=role_id) for role_id in roles_select]
			need_push_asset = set()

			# 授权系统用户必须已经推送到授权的资产上, 否则下面验证不通过
			for role in roles_obj:
				asset_no_push = get_role_push_host(role)[1]		# 获取系统用户没用推送到的资产记录
				need_push_asset.update(set(calc_assets) & set(asset_no_push))
				if need_push_asset:
					raise ServerError(u'没有推送系统用户 %s 的主机 [ %s ]' % (role.name, '|'.join([asset.hostname for asset in need_push_asset])))

			# 授权成功, 写回数据库
			rule = PermRule(name=rule_name, comment=rule_comment)
			rule.save()
			rule.user = users_obj
			rule.user_group = user_groups_obj
			rule.asset = assets_obj
			rule.asset_group = asset_groups_obj
			rule.role = roles_obj
			rule.save()

			msg = u'添加授权规则: %s 成功' % (rule_name, )
			return HttpResponseRedirect(reverse('rule_list'))
		except ServerError, e:
			error = e
	return my_render('jperm/perm_rule_add.html', locals(), request)


@require_role('admin')
def perm_rule_edit(request):
	'''
	授权规则编辑视图
	'''
	header_title, path1, path2 = u'授权规则', u'规则管理', u'编辑规则'
	rule_id = request.GET.get('id', '')
	try:
		rule = get_object(PermRule, id=rule_id)
		if not rule:
			raise ServerError(u'授权规则不存在')
	except ServerError, e:
		return HttpResponseRedirect(reverse('rule_list'))

	# 获取授权规则关联的User, UserGroup, Asset, AssetGroup, PermRole
	users = User.objects.all()
	user_groups = UserGroup.objects.all()
	assets = Asset.objects.all()
	asset_groups = AssetGroup.objects.all()
	roles = PermRole.objects.all()

	if request.method == 'POST':		# 获取编辑后的User, UserGroup, Asset, AssetGroup, PermRole
		rule_name = request.POST.get('name', '')
		rule_comment = request.POST.get('comment', '')
		users_select = request.POST.getlist('user', [])
		user_groups_select = request.POST.getlist('user_group', [])
		assets_select = request.POST.getlist('asset', [])
		asset_groups_select = request.POST.getlist('asset_group', [])
		roles_select = request.POST.getlist('role', [])

		try:
			if not rule_name or not roles_select:
				raise ServerError(u'系统用户名称和授权规则名称不能为空')

			test_rule = get_object(PermRule, name=rule_name)
			if test_rule and test_rule.id != rule.id:
				raise ServerError(u'修改后的规则名称[ %s ]有重名' % (rule_name, ))

			# 获取授权规则的资产
			assets_obj = [Asset.objects.get(id=asset_id) for asset_id in assets_select]
			asset_groups_obj = [AssetGroup.objects.get(id=asset_group_id) for asset_group_id in asset_groups_select]
			group_assets_obj = []
			for asset_group in asset_groups_obj:
				group_assets_obj.extend(asset_group.asset_set.all())
			calc_assets = list(set(assets_obj) | set(group_assets_obj))

			# 获取授权规则的User, UserGroup
			users_obj = [User.objects.get(id=user_id) for user_id in users_select]
			user_groups_obj = [UserGroup.objects.get(id=user_group_id) for user_group_id in user_groups_select]

			# 获取授权规则的系统用户
			roles_obj = [PermRole.objects.get(id=rule_id) for rule_id in roles_select]
			need_push_asset = set()

			for role in roles_obj:
				no_push_assets = get_role_push_host(role)[1]
				need_push_asset.update(set(calc_assets) & no_push_assets)
				if need_push_asset:
					raise ServerError(u'没有推送系统用户 %s 的主机 [ %s ]' % (role.name, '|'.join([asset.hostname for asset in need_push_asset])))

			# 授权成功, 修改PermRule表数据
			rule.user = users_obj
			rule.user_group = user_groups_obj
			rule.asset = assets_obj
			rule.asset_group = asset_groups_obj
			rule.role = roles_obj
			rule.name = rule_name
			rule.comment = rule_comment
			rule.save()
			msg = u'编辑授权规则: %s, 成功' % (rule.name, )
		except ServerError, e:
			error = e

	return my_render('jperm/perm_rule_edit.html', locals(), request)


@require_role('admin')
def perm_rule_delete(request):
	'''
	删除授权规则视图
	'''

	if request.method == 'POST':
		rule_id = request.POST.get('id', '')
		rule = get_object(PermRule, id=rule_id)
		if rule:
			rule.delete()
			return HttpResponse(u'删除授权规则: %s 成功' % (rule.name, ))

	return HttpResponseNotAllowed(u'操作不被容许!!!')
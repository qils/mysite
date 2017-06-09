#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from __future__ import unicode_literals

import re
from jperm.perm_api import *
from django.db.models import Q
from jperm.utils import trans_all
from django.shortcuts import render
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


def perm_role_list(request):
	pass


def perm_role_get(request):
	pass


def perm_role_detail(request):
	pass


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


def perm_rule_add(request):
	pass


def perm_rule_edit(request):
	pass
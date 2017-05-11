#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django import forms
from jasset.models import IDC, Asset, AssetGroup


class IdcForm(forms.ModelForm):
	'''
	IDC表单域
	'''
	class Meta:
		model = IDC
		fields = ['name', 'bandwidth', 'available_bandwidth', 'operator', 'linkman', 'phone', 'address', 'network', 'comment']		# 表单域
		widgets = {
			'name': forms.TextInput(attrs={'placeholder': 'Name'}),
			'network': forms.Textarea(attrs={'placeholder': '192.168.1.0/24\n192.168.2.0/24'})		# 显示其他组件
		}


class AssetForm(forms.ModelForm):
	'''
	资产表单
	'''
	class Meta:
		model = Asset
		fields = [
			'ip', 'other_ip', 'hostname', 'port', 'group', 'username', 'password', 'use_default_auth',
			'idc', 'mac', 'remote_ip', 'brand', 'cpu', 'memory', 'disk', 'system_type', 'system_version',
			'cabinet', 'position', 'number', 'status', 'asset_type', 'env', 'sn', 'is_active', 'comment',
			'system_arch'
		]

#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django import forms
from jasset.models import IDC, Asset, AssetGroup


class IdcForm(forms.ModelForm):
	class Meta:
		model = IDC
		fields = ['name', 'bandwidth', 'operator', 'linkman', 'phone', 'address', 'network', 'comment']
		widgets = {
			'name': forms.TextInput(attrs={'placeholder': 'Name'}),
			'network': forms.Textarea(attrs={'placeholder': '192.168.1.0/24\n192.168.2.0/24'})
		}

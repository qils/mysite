#!/usr/bin/env python
# --*-- coding: utf-8 --*--


def trans_all(str):
	if str.strip().lower() == 'all':
		return str.upper()
	else:
		return str

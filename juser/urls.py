#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django.conf.urls import patterns, include, url


urlpatterns = patterns(
	'juser.views',
	url(r'^password/forget/$', 'forget_password', name='password_forget'),
	url(r'^password/reset/$', 'reset_password', name='password_reset'),
)

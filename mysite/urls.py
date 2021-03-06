#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from django.conf.urls import patterns, include, url

# from django.contrib import admin
# admin.autodiscover()

# urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'mysite.views.home', name='home'),
    # url(r'^blog/', include('blog.urls')),

#    url(r'^admin/', include(admin.site.urls)),
# )


urlpatterns = patterns(
    'mysite.views',
    # Examples:
    url(r'^$', 'index', name='index'),
    url(r'^skin_config/$', 'skin_config', name='skin_config'),
    url(r'^login/$', 'Login', name='login'),
    url(r'^logout/$', 'Logout', name='logout'),
    url(r'^file/upload/$', 'upload', name='file_upload'),
    url(r'^file/download/$', 'download', name='file_download'),
    url(r'^terminal/$', 'web_terminal', name='terminal'),
    url(r'^exec_cmd/$', 'exec_cmd', name='exec_cmd'),
    url(r'^setting', 'setting', name='setting'),
    url(r'^juser/', include('juser.urls')),
    url(r'^jasset/', include('jasset.urls')),
    url(r'^jperm/', include('jperm.urls')),
    url(r'^jlog/', include('jlog.urls')),
)

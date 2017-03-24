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
    url(r'^login/$', 'Login', name='login'),
    url(r'^juser/', include('juser.urls')),
    url(r'^jasset/', include('jasset.urls')),
)

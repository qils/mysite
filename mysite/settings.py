#!/usr/bin/env python
# --*-- coding: utf-8 --*--
"""
Django settings for mysite project.

For more information on this file, see
https://docs.djangoproject.com/en/1.6/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.6/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os
import ConfigParser

config = ConfigParser.ConfigParser()
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
config.read(os.path.join(BASE_DIR, 'jumpserver.conf'))      # 读取jumpserver配置文件


# ======== mail config ========
MAIL_ENABLE = config.get('mail', 'mail_enable')     # 邮箱能否登录
EMAIL_HOST = config.get('mail', 'email_host')       # 邮箱地址
EMAIL_PORT = config.get('mail', 'email_port')       # 邮箱端口
EMAIL_HOST_USER = config.get('mail', 'email_host_user')     # 邮箱登录用户
EMAIL_HOST_PASSWORD = config.get('mail', 'email_host_password')     # 邮箱登录密码
EMAIL_USE_TLS = config.getboolean('mail', 'email_use_tls')      # 是否使用TLS
try:
    EMAIL_USE_SSL = config.getboolean('mail', 'email_use_ssl')      # 是否使用SSL
except ConfigParser.NoOptionError:
    EMAIL_USE_SSL = False
EMAIL_BACKEND = 'django_smtp_ssl.SSLEmailBackend' if EMAIL_USE_SSL else 'django.core.mail.backends.smtp.EmailBackend'  # 发送邮件后端
EMAIL_TIMEOUT = 5       # 发送邮件超时时间

# ======== Log ========
LOG_DIR = os.path.join(BASE_DIR, 'logs')        # jumpserver日志目录
LOG_LEVEL = config.get('base', 'log')       # 设置日志级别
IP = config.get('base', 'ip')           # 服务监听IP地址
PORT = config.get('base', 'port')       # 服务监听端口
KEY = config.get('base', 'key')     # 加密字符KEY, 随机生成的一个16位字符
URL = config.get('base', 'url')     # 密码重置服务器地址
# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.6/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '3wk1&9lf#akrcha6qrpdf*vob_9vm=*p40%8sslypjj+au0zf2'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

TEMPLATE_DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'juser',
    'jasset',
    'jlog',
    'jperm',
    'django_crontab',
    'django.contrib.humanize',
    'mysite',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'mysite.urls'

WSGI_APPLICATION = 'mysite.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.6/ref/settings/#databases
DATABASES = {}
if config.get('db', 'engine') == 'mysql':
    DB_HOST = config.get('db', 'host')
    DB_PORT = config.get('db', 'port')
    DB_USER = config.get('db', 'user')
    DB_PASSWORD = config.get('db', 'password')
    DB_DATABASE = config.get('db', 'database')
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.mysql',
            'NAME': DB_DATABASE,
            'USER': DB_USER,
            'PASSWORD': DB_PASSWORD,
            'HOST': DB_HOST,
            'PORT': DB_PORT,
        }
    }
elif config.get('db', 'engine') == 'sqlite':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': config.get('db', 'database'),
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
        }
    }

# Internationalization
# https://docs.djangoproject.com/en/1.6/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Shanghai'

USE_I18N = True

USE_L10N = True

USE_TZ = False


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.6/howto/static-files/

STATIC_URL = '/static/'
AUTH_USER_MODEL = 'juser.User'
TEMPLATE_DIRS = (os.path.join(BASE_DIR, 'templates'), )
STATICFILES_DIRS = (os.path.join(BASE_DIR, 'static'), )

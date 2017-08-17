#!/usr/bin/env python
# --*-- coding: utf-8 --*--

import os
import shutil
from mysite.api import *
from uuid import uuid4
from paramiko.rsakey import RSAKey
from paramiko import SSHException


def trans_all(str):
	if str.strip().lower() == 'all':
		return str.upper()
	else:
		return str


def gen_keys(key='', key_path_dir=''):
	'''
	创建秘钥对文件, 如果指定key, 则依据key内容来创建, 如果不指定通过paramiko模块创建
	key: 私钥内容
	key_path_dir： 私钥与公钥存放目录
	'''
	key_basename = 'key-' + uuid4().hex
	if not key_path_dir:
		key_path_dir = os.path.join(settings.KEY_DIR, 'role_key', key_basename)		# 指定私钥与公钥存放目录
	private_key = os.path.join(key_path_dir, 'id_rsa')		# 定义私钥文件
	public_key = os.path.join(key_path_dir, 'id_rsa.pub')		# 指定公钥文件
	mkdir(key_path_dir, mode=755)		# 创建私钥和公钥的存放目录

	if not key:		# 不输入私钥, 创建一个密钥
		key = RSAKey.generate(2048)		# 创建key对象
		key.write_private_key_file(private_key)		# 将私钥写入私钥文件
	else:
		with open(private_key, 'w') as f:
			f.write(key)		# 将给定的私钥写入到私钥文件
		with open(private_key) as f:
			try:
				key = RSAKey.from_private_key(f)		# 创建key对象
			except SSHException, e:		# 捕获异常, 删除私钥与公钥存放目录
				shutil.rmtree(key_path_dir, ignore_errors=True)
				raise SSHException(e)
	os.chmod(private_key, 0644)

	with open(public_key, 'w') as content_file:		# 将公钥写入公钥文件
		for data in [key.get_name(), ' ', key.get_base64(), ' %s@%s' % ('root', os.uname()[1])]:
			content_file.write(data)		# key.get_name() 返回字符'ssh-rsa', key.get_base64()返回公钥字符

	return key_path_dir		# 创建完密钥后, 返回密钥存储路径

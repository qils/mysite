#!/usr/bin/env python
# --*-- coding: utf-8 --*--

from ansible.inventory import Inventory


class MyInventory(Inventory):
	def __init__(self, resource):
		self.resource = resource
		self.inventory = Inventory(host_list=[])
		self.gen_inventory()


class MyRunner(MyInventory):
	def __init__(self, *args, **kwargs):
		super(MyRunner, self).__init__(*args, **kwargs)
		self.results_raw = {}


class MyTask(MyRunner):
	def __init__(self, *args, **kwargs):
		super(MyTask, self).__init__(*args, **kwargs)

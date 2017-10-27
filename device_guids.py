#!/usr/bin/env python
import re
import subprocess
import platform
import os

def get_guid(device) :
	device_regex = re.compile("[A-Za-z0-9 ]+ ?(?:\\(([0-9.]+)\\))? \\[([A-F0-9-]+)\\]")
	version_regex = re.compile("([0-9]+)\\.([0-9]+)(?:\\.([0-9]+))?")
	
	command = "instruments -s devices"
	p = subprocess.Popen(command, stdout = subprocess.PIPE, stderr = subprocess.PIPE, shell = True)
	
	# Sometimes the hostname comes back with the proper casing, sometimes not. Using a
	# case insensitive regex ensures we work either way
	dev_name_regex = re.compile("^" + device, re.I)
	
	latest_os_device = None
	latest_os_version = None
	
	for line in p.stdout :
		if (dev_name_regex.match(line) == None) :
			continue
		
		match = device_regex.match(line)
		
		# Regex won't match simulators with apple watches...
		if (match == None) : 
			continue
		
		# If it's Mac OS then there is no leading version # and we can just return it
		if (match.group(1) == None) :
			return match.group(2)
		
		version_match = version_regex.match(match.group(1))
		
		minor_version = version_match.group(3)
		if (minor_version ==  None) :
			minor_version = 0
		version_tuple = (version_match.group(1), version_match.group(2), minor_version)
		
		replace = False
		if (latest_os_version == None) :
			replace = True
		elif (version_tuple[0] > latest_os_version[0]) :
			replace = True
		elif (version_tuple[0] == latest_os_version[0]) :
			if (version_tuple[1] > latest_os_version[1]) :
				replace = True
			elif (version_tuple[1] == latest_os_version[1]) :
				if (version_tuple[2] > latest_os_version[2]) :
					replace = True
		
		if (replace == True) :
			latest_os_device = match.group(2)
			latest_os_version = version_tuple
	
	device_guid = latest_os_device
	return latest_os_device

def get_ios(device) :
	if (get_ios.guid != None) :
		return get_ios.guid
	
	get_ios.guid = get_guid(device)
	return get_ios.guid

get_ios.guid = None

def get_mac() :
	if (get_mac.guid != None) :
		return get_mac.guid
	
	device = subprocess.check_output("hostname -s", shell=True).strip()
	get_mac.guid = get_guid(device)
	return get_mac.guid

get_mac.guid = None
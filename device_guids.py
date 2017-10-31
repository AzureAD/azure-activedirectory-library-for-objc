#!/usr/bin/env python
import re
import subprocess
import platform
import os

def get_guid_i(device) :
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
	
	return latest_os_device

def get_guid(device) :
	guid = get_guid_i(device)
	if (guid == None) :
		print_failure(device)
	return guid

def print_failure(device) :
	print "Failed to find GUID for device : " + device
	subprocess.call("instruments -s devices", shell=True)
	raise Exception("Failed to get device GUID")

def get_ios(device) :
	if (device in get_ios.guid) :
		return get_ios.guid[device]
	
	guid = get_guid(device)
	get_ios.guid[device] = guid
	return guid

get_ios.guid = {}

def get_mac() :
	if (get_mac.guid != None) :
		return get_mac.guid
	
	get_mac.guid = subprocess.check_output("system_profiler SPHardwareDataType | awk '/UUID/ { print $3; }'", shell=True)
	return get_mac.guid

get_mac.guid = None
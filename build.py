#!/usr/bin/env python

import subprocess
import sys

ios_sim_dest = "-destination 'platform=iOS Simulator,name=iPhone 6,OS=latest'"
ios_sim_flags = "-sdk iphonesimulator CODE_SIGN_IDENTITY=\"\" CODE_SIGNING_REQUIRED=NO"

default_workspace = "ADAL.xcworkspace"

class tclr:
	HDR = '\033[1m'
	OK = '\033[32m\033[1m'
	FAIL = '\033[31m\033[1m'
	WARN = '\033[33m\033[1m'
	SKIP = '\033[96m\033[1m'
	END = '\033[0m'

build_targets = [
	{
		"name" : "iOS Framework",
		"scheme" : "ADAL",
		"operations" : [ "build", "test" ],
		"platform" : "iOS",
	},
	{
		"name" : "iOS Test App",
		"scheme" : "MyTestiOSApp",
		"operations" : [ "build" ],
		"platform" : "iOS"
	},
	{
		"name" : "Sample Swift App",
		"scheme" : "SampleSwiftApp",
		"operations" : [ "build" ],
		"platform" : "iOS"
	},
	{
		"name" : "Mac Framework",
		"scheme" : "ADAL Mac",
		"operations" : [ "build", "test" ],
		"platform" : "Mac"
	},
	{
		"name" : "Mac Framework 32-bit",
		"scheme" : "ADAL Mac",
		"operations" : [ "build", "test" ],
		"platform" : "Mac",
		"arch" : "i386"
	},
	{
		"name" : "Mac Test App",
		"scheme" : "MyTestMacOSApp",
		"operations" : [ "build" ],
		"platform" : "Mac"
	}
]

def print_operation_start(name, operation) :
	print tclr.HDR + "Beginning " + name + " [" + operation + "]" + tclr.END
	print "travis_fold:start:" + (name + "_" + operation).replace(" ", "_")

def print_operation_end(name, operation, exit_code) :
	print "travis_fold:end:" + (name + "_" + operation).replace(" ", "_")

	if (exit_code == 0) :
		print tclr.OK + name + " [" + operation + "] Succeeded" + tclr.END
	else :
		print tclr.FAIL + name + " [" + operation + "] Failed" + tclr.END

def do_ios_build(target, operation) :
	name = target["name"]
	scheme = target["scheme"]

	print_operation_start(name, operation)

	command = "xcodebuild " + operation + " -workspace " + default_workspace + " -scheme \"" + scheme + "\" -configuration CodeCoverage " + ios_sim_flags + " " + ios_sim_dest + " | xcpretty"
	print command
	exit_code = subprocess.call("set -o pipefail;" + command, shell = True)

	print_operation_end(name, operation, exit_code)
	return exit_code

def do_mac_build(target, operation) :
	arch = target.get("arch")
	name = target["name"]
	scheme = target["scheme"]

	print_operation_start(name, operation)

	command = "xcodebuild " + operation + " -workspace " + default_workspace + " -scheme \"" + scheme + "\""

	if (arch != None) :
		command = command + " -destination 'arch=" + arch + "'"

	command = command + " | xcpretty"

	print command
	exit_code = subprocess.call("set -o pipefail;" + command, shell = True)

	print_operation_end(name, operation, exit_code)

	return exit_code

build_status = dict()

def check_dependencies(target) :
	dependencies = target.get("dependencies")
	if (dependencies == None) :
		return True

	for dependency in dependencies :
		dependency_status = build_status.get(dependency)
		if (dependency_status == None) :
			print tclr.SKIP + "Skipping " + name + " dependency " + dependency + " not built yet." + tclr.END
			build_status[name] = "Skipped"
			return False

		if (build_status[dependency] != "Succeeded") :
			print tclr.SKIP + "Skipping " + name + " dependency " + dependency + " failed." + tclr.END
			build_status[name] = "Skipped"
			return False

	return True

clean = True

for arg in sys.argv :
	if (arg == "--no-clean") :
		clean = False

# start by cleaning up any derived data that might be lying around
if (clean) :
	subprocess.call("rm -rf ~/Library/Developer/Xcode/DerivedData/ADAL-*", shell=True)

for target in build_targets:
	exit_code = 0
	name = target["name"]
	platform = target["platform"]

	# If we don't have the dependencies for this target built yet skip it.
	if (not check_dependencies(target)) :
		continue

	for operation in target["operations"] :
		if (exit_code != 0) :
			break; # If one operation fails, then the others are almost certainly going to fail too

		if (platform == "iOS") :
			exit_code = do_ios_build(target, operation)
		elif (platform == "Mac") :
			exit_code = do_mac_build(target, operation)
		else :
			raise Exception('Unrecognized platform type ' + platform)

	if (exit_code == 0) :
		print tclr.OK + name + " Succeeded" + tclr.END
		build_status[name] = "Succeeded"
	else :
		print tclr.FAIL + name + " Failed" + tclr.END
		build_status[name] = "Failed"

final_status = 0

print "\n"

for target in build_targets :
	project = target["name"]
	status = build_status[project]
	if (status == "Failed") :
		print tclr.FAIL + project + " failed." + tclr.END
		final_status = 1
	elif (status == "Skipped") :
		print tclr.SKIP + '\033[93m' + project + " skipped." + tclr.END
		final_status = 1
	elif (status == "Succeeded") :
		print tclr.OK + '\033[92m' + project + " succeeded." + tclr.END
	else :
		raise Exception('Unrecognized status: ' + status)

sys.exit(final_status)

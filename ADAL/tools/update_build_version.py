#!/usr/bin/python

import sys, os, subprocess, re

def read_verfile(name):
    ver_high = None
    ver_low = None
    ver_patch = None
    verfile = open(name, "r")
    for line in verfile:
        match = re.match(r"^#define\s+ADAL_VER_HIGH\s+(\S+)", line)
        if match:
            ver_high = match.group(1).rstrip()
        match = re.match(r"^#define\s+ADAL_VER_LOW\s+(\S+)", line)
        if match:
            ver_low = match.group(1).rstrip()
        match = re.match(r"^#define\s+ADAL_VER_PATCH\s+(\S+)", line)
        if match:
            ver_patch = match.group(1).rstrip()
    verfile.close()
    return '.'.join([ver_high, ver_low, ver_patch])

def set_plist_version(plistname, version):
    if not os.path.exists(plistname):
        print("{0} does not exist".format(plistname))
        return False
    
    plistbuddy = '/usr/libexec/Plistbuddy'
    if not os.path.exists(plistbuddy):
        print("{0} does not exist".format(plistbuddy))
        return False
    
    cmdline = [plistbuddy,
               "-c", "Set CFBundleShortVersionString {0}".format(version),
               plistname]
    if subprocess.call(cmdline) != 0:
        print("Failed to update {0}".format(plistname))
        return False
    
    print("Updated {0} with v{1}".format(plistname, version))
    return True

if __name__ == "__main__":
    
    if len(sys.argv) < 3:
        print("Command in Run Script not properly set. Usage: {0} version_file Info.plist [... Info.plist]".format(sys.argv[0]))
        sys.exit(1)
    vername = sys.argv[1]

    version = read_verfile(vername)
    if version == None:
        print("No version has been read.")
        sys.exit(2)

    for i in range(2, len(sys.argv)):
        plistname = sys.argv[i]
        print(plistname)
        set_plist_version(plistname, version)
    
    sys.exit(0)
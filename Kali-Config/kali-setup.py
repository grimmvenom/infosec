#!/usr/bin/python3
"""
Summary:
		Script to dynamically build vagrant file to setup / configure kali linux.
		Then use ansible.yml file to auto configure using your own unique configuration.
		Encrypt the virtual hard disk to ensure project security.

author:
GrimmVenom <grimmvenom@gmail.com>
Tony Karre @tonykarre (https://github.com/tonykarre/Vagrant-Kali-Project-Setup-Tool)

"""

import os, sys, time, argparse
from pathlib import Path
import platform, subprocess
import netifaces
from shutil import copyfile
import fileinput


def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument('-d', "--directory", action='store', dest='vm_dir', required=False, help='-d <directory>')
	parser.add_argument('-a', '--app', '-p', '--project', action='store', dest="vm_name", required=False, help='-a <app>')
	arguments = parser.parse_args()
	
	arguments.home_dir = str(Path.home())
	arguments.current_dir = os.path.dirname(__file__)
	# parent_dir = os.path.abspath(os.path.join(current_dir, os.pardir))  # Get Parent of Current Directory of Script
	
	if not arguments.vm_dir:
		arguments.vm_dir = str(Path.home()) + os.sep + "Virtual_Machines"
	
	if not arguments.vm_name:
		arguments.vm_name = input("Please enter virtual machine / project name: ")
		if len(arguments.vm_name) > 1:
			print("VM / Project name set to:  " + str(arguments.vm_name))
		else:
			parser.error("Please enter a valid VM / Project name")
	
	return arguments


def setup_vm_dir():
	if not os.path.exists(arguments.vm_dir + os.sep + arguments.vm_name):  # Check if project directories exist
		os.makedirs(arguments.vm_dir + os.sep + arguments.vm_name)  # Creates project directories if they do not exist
	else:
		print("Project already exists!")


def determine_nic():
	# interfaces = netifaces.interfaces()
	gws = netifaces.gateways()
	gateway = gws['default'][netifaces.AF_INET]
	print("NIC in use: ", str(gateway[1]))
	print("NIC IP: ", str(gateway[0]))


def verify_application(app):
	print("Checking PATH for ", str(app))
	cmd = "where" if platform.system() == "Windows" else "which"
	try:
		# subprocess.call([cmd, app])
		result = subprocess.check_output(cmd + " " + app, shell=True)
		if result:
			print("[+] ", str(app), " Found in PATH\n")
	except:
		print("[-] ", str(app), " NOT Found in PATH")


def check_requirements():
	requirements = ["vagrant", "virtualbox", "VBoxManage"]
	if platform.system() == "Windows":
		for item in requirements:
			item = item + ".exe"
		requirements.append("manage-bde.exe")
	print("\n")
	for app in requirements:
		verify_application(app)
	print("\n")


def patch_vagrant():
	"""
	# Now let's see if we have to patch Vagrant.
	#
	# Here's the issue - We will be creating a VM that has an encrypted storage device.
	# When VirtualBox boots up the VM, it will "pause" to allow you to type in the encryption password.
	# Unfortunately, vagrant doesn't realize this is going to happen.  When vagrant boots the VM, it
	# monitors the state of the box to make sure that all is well.  The allowable machine states are "starting" and "running".
	# When vagrant sees "paused", it considers that to be an error state and aborts the rest of the startup process.
	# The box will still boot, but post-boot steps like setting up the synced folder won't happen.

	# So the workaround is to patch vagrant by adding "paused" to the allowable machine states in the "self.action_boot" section of the file action.rb, found in a path like this:
	# Get the root path of our vagrant executable:
	#    Windows Example: C:\\HashiCorp\\Vagrant\\embedded\\gems\\2.2.5\\gems\\vagrant-2.2.5\\plugins\\providers\\virtualbox\\action.rb
	#    Linux Example:   /opt/vagrant/embedded/gems/gems/vagrant-2.2.5/plugins/providers/virtualbox/action.rb
	
	# We want to change this:
	# b.use WaitForCommunicator, [:starting, :running]
	# to this:
	# b.use WaitForCommunicator, [:starting, :paused, :running]
	# The string "[:starting, :running]" only occurs once in the original file, so we can do a string replace with "[:starting, :paused, :running]"

	"""
	if platform.system() == "Windows":
		root_dir = "C:\\"
	else:
		root_dir = "/"
	file = "action.rb"
	full_path = str()
	print("Locating Vagrant's action.rb configuration file")
	for root, dirs, files in os.walk(root_dir):
		# print("searching", root)
		if file in files:
			print("Found: %s" % str(root + os.sep + file))
			if "vagrant" in root + os.sep + file:
				full_path = root + os.sep + file
			break
	print("Action.rb Path: " + str(full_path) + "\n")
	if not os.path.exists(full_path + ".bak"):
		try:
			with fileinput.FileInput(full_path, inplace=True, backup='.bak') as file:
				for line in file:
					print(line.replace("b.use WaitForCommunicator, [:starting, :running]",
						"b.use WaitForCommunicator, [:starting, :paused, :running]"), end='')
			print("[+] Patched Vagrant to support pause status")
		except Exception as e:
			print("[-] Error Patching " + str(full_path))
			pass
		# copyfile(full_path, full_path + ".bak")
	else:
		print("[+] " + str(full_path) + " Already Patched!")


if __name__ == "__main__":
	virtualDiskSize = 64
	virtualImage = "kalilinux/rolling"
	
	arguments = get_arguments()
	setup_vm_dir()
	determine_nic()
	check_requirements()
	patch_vagrant()
	# Dynamically Build Vagrant File
	# Vagrant Up
	# Vagrant Halt
	# Encypt virtual hard disk
#!/usr/bin/python3
"""
Summary:
		Script to dynamically build vagrant file to setup / configure kali linux.
		Then use ansible.yml file to auto configure using your own unique configuration.
		Encrypt the virtual hard disk to ensure project security.

author:
GrimmVenom <grimmvenom@gmail.com>
Tony Karre @tonykarre (https://github.com/tonykarre/Vagrant-Kali-Project-Setup-Tool)

Resources:
	https://www.altaro.com/hyper-v/understanding-working-vhdx-files/
	https://www.tecmint.com/create-virtual-harddisk-volume-in-linux/
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
		arguments.vm_name = input("Please enter virtual machine / project name: ").title()
		if len(arguments.vm_name) > 1:
			print("\nVM / Project name set to:  " + str(arguments.vm_name))
		else:
			parser.error("Please enter a valid VM / Project name")
	
	return arguments


def setup_vm_dir():
	if not os.path.exists(arguments.vm_dir + os.sep + arguments.vm_name):  # Check if project directories exist
		print("\n[+] Creating Project: " + str(arguments.vm_name))
		os.makedirs(arguments.vm_dir + os.sep + arguments.vm_name)  # Creates project directories if they do not exist
	else:
		print("\n[+] Project" + str(arguments.vm_name) + " already exists!")


def determine_nic():
	# interfaces = netifaces.interfaces()
	gws = netifaces.gateways()
	gateway = gws['default'][netifaces.AF_INET]
	print("NIC in use: ", str(gateway[1]))
	print("NIC IP: ", str(gateway[0]))
	return gateway[0], gateway[1]


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


def generate_vagrantfile():
	vagrantfile_path = arguments.vm_dir + os.sep + arguments.vm_name + os.sep + 'vagrantfile'
	if not os.path.exists(vagrantfile_path):
		data = "# -*- mode: ruby -*-\n"
		data += "# vi: set ft=ruby :\n"
		data += "\n# The most common configuration options are documented and commented below.\n"
		data += "# For a complete reference, please see the online documentation at https://docs.vagrantup.com.\n"
		data += "# Every Vagrant development environment requires a box. You can search for boxes at https://vagrantcloud.com/search.\n"
		data += 'Vagrant.configure("2") do |config|\n'
		data += "\tconfig.vm.define :silence do |vm_config|\n"
		data += '\t\tvm_config.vm.hostname = "' + str(arguments.vm_name) + '"\n'
		data += '\t\tvm_config.vm.box = "' + str(virtualImage) + '"\n'
		data += "\t\tvm_config.vm.box_check_update = true\n"
		data += "\t\tvm_config.vm.boot_timeout = 120\n"
		data += "\t\t# Defind Virtualbox VM Specifications\n"
		data += "\t\tvm_config.vm.provider :virtualbox do |v|\n"
		data += '\t\t\tv.name = "' + str(arguments.vm_name) + '"\n'
		data += "\t\t\tv.memory = 4096\n"
		data += "\t\t\tv.cpus = 2\n"
		data += "\t\t\tv.gui = true\n"
		data += "\t\tend\n"
		data += '\t\t# vm_config.vm.synced_folder "~/Scripts", "~/shared_dir"\n'
		data += "\n\t\t# Configure NIC\n"
		data += '\t\tvm_config.vm.network "public_network", use_dhcp_assigned_default_route: true, bridge: "' + str(nic) + '"\n\n'
		data += "\t\t# Suggest Adding Wait Timer before Ansible configuration\n"
		data += "\t\t# Run Ansible Configuration\n"
		data += '\t\tvm_config.vm.provision "ansible_local" do |ansible|\n'
		data += '\t\t\tansible.playbook = "ansible.yml"\n'
		data += "\t\tend\n"
		data += '\t# vm_config.vm.provision :shell, :path => "bootstrap.sh"\n'
		data += "\tend\n"
		data += "end\n"
		# print(data)
		f = open(vagrantfile_path, 'w')
		f.write(data)  # python will convert \n to os.linesep
		f.close()  # you can omit in most cases as
		print("[+] Generated vagrantfile " + str(vagrantfile_path) + "\n")
	else:
		print("[-] vagrantfile already exists!")
		print("Will not generate new vagrantfile in case modifications were made to: " + str(vagrantfile_path))
	return vagrantfile_path


def create_linux_virtual_drive():
	# https://www.tecmint.com/create-virtual-harddisk-volume-in-linux/
	print("Creating VHD on Linux")
	# Create 1 GB VHD Image
	# dd if=/dev/zero of=<project>.img bs=1M count=1024
	
	# Format as EXT4 filesystem
	# sudo mkfs -t ext4 ./<project>.img
	
	# Mount the VHD to access it's volume
	# sudo mkdir /mnt/<project>
	# sudo mount -t auto -o loop ./1GB_HDD.img /mnt/<project>
	
	# To Unmount:
	# sudo umount /mnt/<project>
	# sudo rm ./<project>.img
	
	# vagrant "init" "--template" "`"$erbtemplatefile`"" "--output" "`"$($projfolder)\Vagrantfile`"" "$vagrantbox"


if __name__ == "__main__":
	virtualDiskSize = 64
	virtualImage = "kalilinux/rolling"
	
	arguments = get_arguments()
	setup_vm_dir()  # Prep Project Folder
	ip, nic = determine_nic()  # Get NIC information
	check_requirements()  # Verify necessary applications are installed
	patch_vagrant()  # Patch Vagrants' action.rb file
	vagrantfile_path = generate_vagrantfile()  # Generate Vagrantfile in project folder
	
	# $Virtualdiskfile = "$projfolder\$($projname).vhdx"
	# Create VirtualHardDisk
	# Mount Virtual HD
	# encrypt Virtual HD
	#   # Run the Vagrant init process to build our unique Vagrantfile from the template
	#
	#   Write-Host "[+] Running `"vagrant init`""
	#
	#   & $vagrantexe "init" "--template" "`"$erbtemplatefile`"" "--output" "`"$($projfolder)\Vagrantfile`"" "$vagrantbo
	# Move / download ansible.yml file
	# Vagrant Provision
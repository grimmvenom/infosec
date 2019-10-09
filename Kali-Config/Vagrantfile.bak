# -*- mode: ruby -*-
# vi: set ft=ruby :

# The most common configuration options are documented and commented below.
# For a complete reference, please see the online documentation at
# https://docs.vagrantup.com.

# Every Vagrant development environment requires a box. You can search for
# boxes at https://vagrantcloud.com/search.

Vagrant.configure("2") do |config|
  config.vm.define :silence do |vm_config|
    vm_config.vm.hostname = "Silence"
    vm_config.vm.box = "kalilinux/rolling"
    vm_config.vm.box_check_update = true
    vm_config.vm.boot_timeout = 120
    # Defind Virtualbox VM Specifications
    vm_config.vm.provider :virtualbox do |v|
      v.name = "Silence"
      v.memory = 4096
      v.cpus = 2
      v.gui = true
    end
    # vm_config.vm.synced_folder "~/Scripts", "~/shared_dir"

    # Configure NIC
    vm_config.vm.network "public_network",
      use_dhcp_assigned_default_route: true,
      bridge: "en0: Wi-Fi (AirPort)"

    # Suggest Adding Wait Timer before Ansible configuration

    # Run Ansible Configuration
    vm_config.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "kali-config.yml"
    end

  # vm_config.vm.provision :shell, :path => "bootstrap.sh"
  end
end

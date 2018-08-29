# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrant Documentation: https://docs.vagrantup.com/v2/
# More boxes at: https://app.vagrantup.com

# Prerequisites: latest versions of Vagrant and VirtualBox
# If you're on Linux, do NOT use apt/yum to install these. They are severly out of date.

# Usage: Navigate to the folder containing this file in your CLI (Windows CMD, Linux BASH)
#	Create VM:        "vagrant up"
#	Destroy VM:       "vagrant destroy"
# Power down VM:    "vagrant down"
# Power on VM:      "vagrant up"
# VM Command line:  "vagrant ssh"

# To Provision after creation (useful for testing changes to provisioning scripts):
#   "vagrant provision"


# Installation of Vagrant Plugins
# Source: http://stackoverflow.com/a/28801317
# TODO: plugin installs are borken on Windows 10 as of Vagrant 2.1.2
# required_plugins = %w(vagrant-vbguest) # vagrant-share
# plugins_to_install = required_plugins.select { |plugin| not Vagrant.has_plugin? plugin }
# if not plugins_to_install.empty?
#   puts "Installing Vagrant plugins: #{plugins_to_install.join(' ')}"
#   if system "vagrant plugin install #{plugins_to_install.join(' ')}"
#     exec "vagrant #{ARGV.join(' ')}"
#   else
#     abort "Installation of one or more Vagrant plugins has failed. Aborting..."
#   end
# end


Vagrant.configure(2) do |config|

  # CentOS 7 headless testing VM
  config.vm.define "centos" do |centos|
    centos.vm.box = "centos/7"
    centos.vm.box_check_update = true

    # Network Configuration 
    # NOTE: Vagrant will setup NAT by default, as well as local SSH access.
    # Access ssh using: vagrant ssh
    # If you want to test externally, allow remote access, etc
    #  config.vm.network "forwarded_port", guest: 80, host: 3000
    # config.vm.network "private_network", ip: "192.168.10.10"
    # config.vm.network "forwarded_port", guest: 80, host: 8080, host_ip: "127.0.0.1"
    centos.vm.host_name = "getmac-centos7"

    # NOTE
    #   Vagrant automatically creates a /vagrant share on the guest
    #   This share contains all files in the folder the vagrantfile was run in
    #   Only create a new share for sideloading large files you don't want on Git
    # IMPORTANT: COMMENT OUT BEFORE MERGING INTO MASTER (Your host path could cause issues)
    # "<host_path>", "guest_path"
    # config.vm.synced_folder "../data", "/vagrant_data"
      
    # VirtualBox provider configuration
    centos.vm.provider "virtualbox" do |vb|
      # Display the VirtualBox GUI when booting the machine
      vb.gui = false
      # Customize the amount of memory on the VM. 2GB is reccomended.
      vb.memory = "1024"
      # Add more cores as neccessary. 1 is reccomended.
      vb.cpus = 1
      # VM name in VirtualBox
      vb.name = "getmac-CentOS7-Testbox"
    end

    # Provisioning and setup of the system
    # Inline script:    config.vm.provision "shell", inline: "shell_commands"
    # Script in a file: config.vm.provision "shell", path: "<path_to_script>.sh"
    centos.vm.provision "shell", path: "scripts/centos-provision.sh", privileged: false
  end
  
end

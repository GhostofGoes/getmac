# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrant Documentation: https://docs.vagrantup.com/v2/
# More boxes at: https://app.vagrantup.com

# Prerequisites: latest versions of Vagrant and VirtualBox
# If you're on Linux, do NOT use apt/yum to install, they are severely outdated.
# Instead, download the .deb from https://www.vagrantup.com/downloads.html,
# and install using "sudo apt install ./<file>.deb".

# Usage: Navigate to the folder containing this file in your CLI (Windows CMD, Linux BASH)
# Create VM:        "vagrant up [name]"
# Destroy VM:       "vagrant destroy [name]"
# Power down VM:    "vagrant down [name]"
# Power on VM:      "vagrant up [name]"
# VM Command line:  "vagrant ssh [name]"
# Provision:        "vagrant provision [name]"

# Example: "vagrant up centos" creates a CentOS 7 dev/test machine

# Installation of Vagrant Plugins
# Source: http://stackoverflow.com/a/28801317
# TODO: plugin installs are broken on Windows 10 as of Vagrant 2.1.2
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
  # CentOS 7
  config.vm.define "centos" do |centos|
    centos.vm.box = "centos/7"
    centos.vm.box_check_update = true
    centos.vm.host_name = "getmac-centos7"
    centos.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "1024"
      vb.name = "getmac-CentOS-7"
    end
    centos.vm.provision "shell", path: "scripts/centos-provision.sh", privileged: false
  end

  # OpenBSD 6
  config.vm.define "openbsd" do |openbsd|
    openbsd.vm.box = "generic/openbsd6"
    openbsd.vm.host_name = "getmac-openbsd"
    openbsd.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "512"
      vb.name = "getmac-OpenBSD-6"
    end
  end

  # NetBSD 8
  config.vm.define "netbsd" do |netbsd|
    netbsd.vm.box = "generic/netbsd8"
    netbsd.vm.host_name = "getmac-netbsd"
    netbsd.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "512"
      vb.name = "getmac-NetBSD-8"
    end
  end

  # FreeBSD 11 (version currently used by PFSense)
  config.vm.define "freebsd" do |freebsd|
    freebsd.vm.box = "generic/freebsd11"
    freebsd.vm.host_name = "getmac-freebsd"
    freebsd.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "512"
      vb.name = "getmac-FreeBSD-12"
    end
  end

  # OpenSUSE 42
  config.vm.define "opensuse" do |opensuse|
    opensuse.vm.box = "generic/opensuse42"
    opensuse.vm.host_name = "getmac-opensuse"
    opensuse.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "512"
      vb.name = "getmac-OpenSUSE-42"
    end
  end
  
end

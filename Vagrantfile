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
# Power down VM:    "vagrant halt [name]"
# Power on VM:      "vagrant up [name]"
# VM Command line:  "vagrant ssh [name]"
# Provision:        "vagrant provision [name]"

# Example: "vagrant up centos" creates a CentOS 7 dev/test machine

# Available VMs:
#   osx
#   ubuntu12, ubuntu18, centos7
#   openbsd, freebsd, netbsd
#   opensuse, solaris
#   winserver, win7, win10, win11

# NOTE: files from this directory are mounted to "/vagrant" in the VM
# This only works if guest additions are installed and the proper version.
#   Potential workaround: vagrant plugin install vagrant-vbguest

# NOTE: for Android, use the official emulators included with Android Studio

# wget --no-check-certificate https://github.com/GhostofGoes/getmac/archive/refs/heads/refactor.tar.gz
# tar -xzvf refactor.tar.gz

Vagrant.configure(2) do |config|

  # MacOS (not sure if this works)
  config.vm.define "osx" do |osx|
    osx.vm.box = "jhcook/macos-sierra"
    #osx.vm.box = "adasilva/Mojave"
    osx.vm.host_name = "getmac-osx"
    osx.vm.boot_timeout = 1440
    osx.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "4096"
      vb.name = "getmac-osx-mojave"
      # Fix errors (source: https://github.com/mbigras/macos-vagrant)
      vb.customize ["modifyvm", :id, "--usb", "on"]
      vb.customize ["modifyvm", :id, "--usbehci", "off"]
    end
    osx.vbguest.auto_update = false
  end

  # Ubuntu 12.04 LTS
  config.vm.define "ubuntu12" do |ubuntu12|
    ubuntu12.vm.box = "hashicorp/precise32"
    ubuntu12.vm.host_name = "getmac-ubuntu12"
    ubuntu12.vm.boot_timeout = 1440
    ubuntu12.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "2048"
      vb.name = "getmac-Ubuntu-1204"
    end
    ubuntu12.vbguest.auto_update = false
  end

  # Ubuntu 18.04 LTS
  config.vm.define "ubuntu18" do |ubuntu18|
    ubuntu18.vm.box = "generic/ubuntu1804"
    ubuntu18.vm.host_name = "getmac-ubuntu18"
    ubuntu18.vm.boot_timeout = 1440
    ubuntu18.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "2048"
      vb.name = "getmac-Ubuntu-1804"
    end
    ubuntu18.vm.provision "shell", path: "scripts/ubuntu-provision.sh", privileged: false
  end

  # CentOS 7
  config.vm.define "centos7" do |centos7|
    centos7.vm.box = "centos/7"
    centos7.vm.host_name = "getmac-centos7"
    centos7.vm.boot_timeout = 1440
    centos7.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "1024"
      vb.name = "getmac-CentOS-7"
    end
    centos7.vbguest.auto_update = false
    centos7.vm.provision "shell", path: "scripts/centos-provision.sh", privileged: false
  end

  # OpenBSD 6
  config.vm.define "openbsd" do |openbsd|
    openbsd.vm.box = "generic/openbsd6"
    openbsd.vm.host_name = "getmac-openbsd"
    openbsd.vm.boot_timeout = 1440
    openbsd.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "1024"
      vb.name = "getmac-OpenBSD-6"
    end
    openbsd.vbguest.auto_update = false
    openbsd.vm.provision "shell", path: "scripts/openbsd-provision.sh", privileged: false
  end

  # NetBSD 8
  config.vm.define "netbsd" do |netbsd|
    netbsd.vm.box = "generic/netbsd8"
    netbsd.vm.host_name = "getmac-netbsd"
    netbsd.vm.boot_timeout = 1440
    netbsd.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "1024"
      vb.name = "getmac-NetBSD-8"
    end
    netbsd.vbguest.auto_update = false
    # To test code:
    #   wget --no-check-certificate https://github.com/ghostofgoes/getmac/archive/refactor.zip
    #   sudo pkgin install python37
    #
    # NOTE: this requires SMB, since no guest extensions
    # netbsd.vm.synced_folder ".", "/home/vagrant/getmac"
  end

  # FreeBSD 11 (version currently used by PFSense)
  config.vm.define "freebsd" do |freebsd|
    freebsd.vm.box = "generic/freebsd11"
    freebsd.vm.host_name = "getmac-freebsd"
    freebsd.vm.boot_timeout = 1440
    freebsd.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "1024"
      vb.name = "getmac-FreeBSD-12"
    end
    freebsd.vbguest.auto_update = false
  end

  # OpenSUSE 42
  config.vm.define "opensuse" do |opensuse|
    opensuse.vm.box = "generic/opensuse42"
    opensuse.vm.host_name = "getmac-opensuse"
    opensuse.vm.boot_timeout = 1440
    opensuse.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "1024"
      vb.name = "getmac-OpenSUSE-42"
    end
    opensuse.vbguest.auto_update = false
  end

  # Solaris 10
  # NOTE: this box appears to have working guest extensions so the 
  # local directory (and code) will be available in the VM at "/vagrant"
  config.vm.define "solaris" do |solaris|
    solaris.vm.box = "tnarik/solaris10-minimal"
    solaris.vm.host_name = "getmac-solaris"
    solaris.vm.boot_timeout = 1440
    solaris.vm.provider "virtualbox" do |vb|
      vb.gui = false
      vb.memory = "1024"
      vb.name = "getmac-Solaris-10"
    end
    solaris.vbguest.auto_update = false
    solaris.vm.provision "shell", path: "scripts/solaris-provision.sh", privileged: false
  end

  # Windows Server 2012 R2
  config.vm.define "winserver" do |winserver|
    winserver.vm.box = "opentable/win-2012r2-standard-amd64-nocm"
    winserver.vm.host_name = "getmac-winserver"
    winserver.vm.boot_timeout = 1440
    winserver.vm.provider "virtualbox" do |vb|
      vb.gui = true
      vb.memory = "2048"
      vb.name = "getmac-Windows-Server-2012R2"
    end
  end

  # Windows 7
  config.vm.define "win7" do |win7|
    win7.vm.box = "datacastle/windows7"
    win7.vm.host_name = "getmac-win7"
    win7.vm.boot_timeout = 1440
    win7.vm.provider "virtualbox" do |vb|
      vb.gui = true
      vb.memory = "2048"
      vb.name = "getmac-Windows-7"
    end
  end

  # Windows 10
  config.vm.define "win10" do |win10|
    win10.vm.box = "Microsoft/EdgeOnWindows10"
    win10.vm.host_name = "getmac-win10"
    win10.vm.boot_timeout = 1440
    win10.vm.provider "virtualbox" do |vb|
      vb.gui = true
      vb.memory = "2048"
      vb.name = "getmac-Windows-10"
    end
  end

  # Windows 11
  config.vm.define "win11" do |win11|
    win11.vm.box = "gusztavvargadr/windows-11"
    win11.vm.host_name = "getmac-win11"
    win11.vm.boot_timeout = 1440
    win11.vm.provider "virtualbox" do |vb|
      vb.gui = true
      vb.memory = "2048"
      vb.name = "getmac-Windows-11"
    end
  end

end

# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"
  # config.vm.box_check_update = false
  config.vm.network "forwarded_port", guest: 2375, host: 2375, host_ip: "127.0.0.1"

  # config.vm.synced_folder "../data", "/vagrant_data"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:

  config.vm.provider "virtualbox" do |vb|
    # Display the VirtualBox GUI when booting the machine
    # vb.gui = true
    vb.memory = "2048"
  end

  # View the documentation for the provider you are using for more
  # information on available options.

  # Enable provisioning with a shell script. Additional provisioners such as
  # Puppet, Chef, Ansible, Salt, and Docker are also available. Please see the
  # documentation for more information about their specific syntax and use.

  config.vm.provision "docker" do |d|
    d.post_install_provision "shell", inline:"echo export http_proxy='http://127.0.0.1:3128/' >> /test"
    d.pull_images "hello-world"
    d.pull_images "ubuntu"
  end

  config.vm.provision "shell", inline: <<-SHELL
     apt-get update
     apt-get install -y pkg-config zip g++ zlib1g-dev unzip python
     wget -nv https://github.com/bazelbuild/bazel/releases/download/0.21.0/bazel-0.21.0-installer-linux-x86_64.sh
     chmod +x bazel-0.21.0-installer-linux-x86_64.sh
     ./bazel-0.21.0-installer-linux-x86_64.sh
     cd /vagrant && bazel build runsc
     echo ewogICAgImRlZmF1bHQtcnVudGltZSI6ICJydW5zYyIsCiAgICAicnVudGltZXMiOiB7CiAgICAgICAgInJ1bnNjIjogewogICAgICAgICAgICAicGF0aCI6ICIvdmFncmFudC9iYXplbC1iaW4vcnVuc2MvbGludXhfYW1kNjRfcHVyZV9zdHJpcHBlZC9ydW5zYyIKICAgICAgICB9CiAgICB9Cn0K | base64 -d > /etc/docker/daemon.json
     sed -i 's/-H .*/\0 -H tcp:\/\/0.0.0.0:2375/' /lib/systemd/system/docker.service
     systemctl daemon-reload
     systemctl restart docker      
  SHELL
end

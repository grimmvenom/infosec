#!/bin/bash

# Update sources.list if latest kali repo not included
function system_update {
  if grep -Fxq "deb http://http.kali.org/kali kali-rolling main non-free contrib" /etc/apt/sources.list
  then
    echo "Kali Source already Exists"
  else
    echo "\ndeb http://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list
  fi

  apt update
  apt -y upgrade
  apt --fix-broken install
  apt install -y alacarte
  apt install -y fish
  chsh -s /usr/bin/fish
  apt install -y virtualbox-guest-x11
  mount -t vboxsf vbox_shared_folder /media/vbox_shared_folder
}

# install version of Firefox
function update_firefox {
  VERSION=64.0
  cd ~/Downloads
  # Check if bc is installed
  if ! [ -x "$(command -v bc)" ]; then
    apt install -y bc
  fi

  # Check if Firefox is installed
  if ! [ -x "$(command -v firefox)" ]; then
    echo "Error: Firefox not installed"
    if [ ! -f "./firefox-${VERSION}.tar.bz2" ]; then
      # Download version
      wget "https://download-installer.cdn.mozilla.net/pub/firefox/releases/${VERSION}/linux-x86_64/en-US/firefox-${VERSION}.tar.bz2"
      tar xvjf ./*firefox*.tar.bz2
      rm /usr/bin/firefox
      mv ~/Downloads/firefox /opt/
      ln -s /opt/firefox/firefox /usr/bin/firefox
    fi
  else
    INSTALLED_VERSION="$(firefox --version)"
    IFS=' ' read -ra array <<< "$INSTALLED_VERSION"
    # Compar Firefox Versions
    if (( $(echo "$array[-1] $VERSION" | awk '{print ($1 > $2)}') )); then
      echo "Firefox ${array[-1]} OLDER Than $VERSION"
      if [ ! -f "./firefox-${VERSION}.tar.bz2" ]; then
        # Download version
        wget "https://download-installer.cdn.mozilla.net/pub/firefox/releases/${VERSION}/linux-x86_64/en-US/firefox-${VERSION}.tar.bz2"
      fi
    else
      echo "Firefox ${array[-1]} NEWER Than $VERSION"
    fi
  fi

}

function dir_check(){
	echo "Checking Directories"
	echo "============================"
	# Create Applications Directory
	if [ ! -d ~/applications ]; then
		echo "Creating ~/applications directory"
		mkdir -p ~/applications
	else
		echo "~/applications already exists"
	fi

	# Create scripts Directory
	if [ ! -d ~/scripts ]; then
		echo "Creating ~/scripts directory"
		mkdir -p ~/scripts
	else
		echo "~/scripts already exists"
	fi

	echo " "
}


function install_linux_utils() {
	echo "Running Update"
	sudo apt-get update

	# Check for unzip
	App_Status="$(dpkg-query -W -f='${Status} ${Version}\n' unzip)"
	echo "unzip Status: ${App_Status}"
	echo " "
	if [[ ${App_Status} =~ "installed" ]]; then
		echo "unzip is already installed"
	else
		echo "unzip NOT Installed"
		echo "installing unzip"
		sudo apt-get --yes --force-yes install unzip
	fi

	echo " "

	# Check for rsync
	App_Status="$(dpkg-query -W -f='${Status} ${Version}\n' rsync)"
	echo "rsync Status: ${App_Status}"
	echo " "
	if [[ ${App_Status} =~ "installed" ]]; then
		echo "rsync is already installed"
	else
		echo "rsync NOT Installed"
		echo "installing rsync"
		sudo apt-get --yes --force-yes install rsync
	fi

	echo " "
}


function pycharm_setup(){
	echo "Pycharm Setup"
	echo "============================"
	# Create PyCharm Directory
	if [ ! -d ~/applications/pycharm ]; then
		echo "Creating ~/applications/pycharm directory"
		mkdir -p ~/applications/pycharm
		cd ~/Downloads
		wget https://download.jetbrains.com/python/pycharm-community-2016.3.2.tar.gz
		tar -zxf pycharm*.tar.gz
		rm ~/Downloads/pycharm*.tar.gz
		rsync -ah --progress ~/Downloads/pycharm*/* ~/applications/pycharm
		rm -r ~/Downloads/pycharm*
		cd $ScriptDir
		echo " "
	else
		echo "~/applications/pycharm already exists"
	fi

	# Setup PyCharm Alias / Shortcut
	if grep -q "alias pycharm" ~/.bashrc; then
		echo "Pycharm Alias Already Set"
	else
		echo "PyCharm Alias NOT Set"
		echo " " | sudo tee -a ~/.bashrc
		echo "alias pycharm='screen -S pycharm -d -m bash ~/applications/pycharm/bin/pycharm.sh" | sudo tee -a ~/.bashrc
		echo " "
	fi

	echo "PyCharm Setup Complete"
	echo " "
}


function arachni_scanner() {
	echo "Checking for Arachni Scanner"
	echo "============================"
	# Create Applications Directory
	if [ ! -d ~/applications/arachni-scanner ]; then
		echo "Downloading arachni-scanner"
		mkdir -p ~/applications/arachni-scanner
		cd ~/Downloads
		wget "https://github.com/Arachni/arachni/releases/download/v1.4/arachni-1.4-0.5.10-linux-x86_64.tar.gz"
		tar -zxf arachni*.tar.gz
		rm arachni*.tar.gz
		rsync -ah --progress ~/Downloads/arachni*/* ~/applications/arachni-scanner
		rm -r ~/Downloads/arachni*
		cd $ScriptDir
		echo " "
	else
		echo "~/applications/arachni-scanner already exists"
		echo " "
	fi

	# Setup arachni Alias / Shortcut
	if grep -q "alias arachni" ~/.bashrc; then
		echo "arachni Alias Already Set"
	else
		echo "arachni Alias NOT Set"
		echo " " | sudo tee -a ~/.bashrc
		echo "alias arachni='cd ~/applications/arachni-scanner/bin && ls'" | sudo tee -a ~/.bashrc
		echo " "
	fi

	echo "Arachni Setup Complete"
	echo " "
}


# Global variables
######################
Script="$0"
ScriptDir=$(dirname "$Script")

# Run Functions
######################
system_update
#update_firefox
#dir_check
#install_linux_utils
#geany_setup
#pycharm_setup
#arachni_scanner



#!/bin/bash

DEBtools_list=("dirsearch" "gobuster" "nikto" "testssl.sh" "ffuf" "sslscan" "joomscan" "wpscan" "python" "python3-pip" "python3" "ldap-utils" "git" "smbmap" "smbclient" "snmpwalk" "enum4linux" "onesixtyone" "snmp" "odat" "tnscmd10g" "default-jre" "ssh-audit" "redis-tools" "evil-winrm" "libmemcached-tools" "postgresql-client" "ftp" "rsync" "ipmitool" "jq" "curl" "rpcbind" "freerdp2-x11" "rsh-client" "nmap" "dnsrecon" "smtp-user-enum" "snmp-check" "default-mysql-client" "nfs-common")

PIPtools_list=("droopescan" "ldeep" "cottontail-offensive" "impacket" "ajpShooter" "cqlsh")

GOtools_list=("github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")

tools_list=("https://raw.githubusercontent.com/Bhanunamikaze/VulnFinder/main/SMBPentest.sh" "https://github.com/NickstaDB/BaRMIe/releases/download/v1.01/BaRMIe_v1.01.jar" "https://github.com/aquasecurity/kube-hunter/releases/download/v0.6.8/kube-hunter-linux-x86_64-refs.tags.v0.6.8" "https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64" "https://raw.githubusercontent.com/Bhanunamikaze/VMwareAPIPentest/main/ESXi_Soap_Pentest.py")

green=`tput setaf 2`
red=`tput setaf 1`
magenta=`tput setaf 5`
cyan=`tput setaf 6`
reset=`tput sgr0`

echo -e "\n${green}[*] List of Softwares to Validate and Install : ${magenta}${DEBtools_list[@]} nuclei ${PIPtools_list[@]} Kube Hunter etcdctl BeanShooter BaRMIe Remote-method-guesser SmbPentest.sh ${reset}\n"
read -p "Do you want to install missing software? (y/n) " answer
if [[ $answer != "y" ]]; then
exit 0
fi

echo -e "\n${green}########## Start Validation & Installation ########## ${reset} \n"

for tool in "${DEBtools_list[@]}"
do
    if ! [ $(command -v "$tool") ] > /dev/null; then
        echo -e "\n${cyan} [**] $tool is not installed. Installing now... ${reset}"
        sudo apt-get install "$tool" -y
        if [ $? -ne 0 ]; then
            # catch and handle errors while installing
            echo -e "\n ${red}[-] Error: Failed to install $tool ${reset}\n"
        else
        echo -e "\n${magenta} [+] Python Module $tool is now installed ${reset}\n"
        fi
  else
    echo "${green} [*] $tool is already installed ${reset}"
    fi
done


for tool in "${PIPtools_list[@]}"
do
    if ! [ $(command -v "$tool") ]  &> /dev/null; then
        echo -e "\n${cyan} [**] $tool is not installed. Installing now... ${reset}"
        sudo pip install "$tool"
        if [ $? -ne 0 ]; then
            # catch and handle errors while installing
            echo -e "\n ${red}[-] Error: Failed to install $tool ${reset}\n"
        else
        echo -e "\n${magenta} [+] $tool is now installed ${reset}\n"
        fi
  else
    echo "${green} [*] $tool is already installed ${reset}"
    fi
done


for tool in "${GOtools_list[@]}"
do
    tool_name=$(echo $tool | rev | cut -d '/' -f1 | rev | cut -d '@' -f1)
    if ! [ $(command -v "$tool_name") ] > /dev/null; then
        echo -e "\n${cyan} [**] $tool_name is not installed. Installing now... ${reset}"
        go install -v $tool
        if [ $? -ne 0 ]; then
            # catch and handle errors while installing
            echo -e "\n ${red}[-] Error: Failed to install $tool_name ${reset}\n"
        else
        echo -e "\n${magenta} [+] $tool_name is now installed ${reset}\n"
        fi
  else
    echo "${green} [*] $tool_name is already installed ${reset}"
    fi
done


for tool in "${tools_list[@]}"
do
    tool_name=$(echo $tool |rev |  cut -d "/" -f1| rev)
    if ! [ $(command -v "$tool_name") ] > /dev/null; then
        echo -e "\n${cyan} [**] $tool_name is not installed. Installing now... ${reset}"
        sudo wget $tool -O /usr/local/bin/$tool_name
        sudo chmod +x /usr/local/bin/$tool_name
        if [ $? -ne 0 ]; then
            # catch and handle errors while installing
            echo -e "\n ${red}[-] Error: Failed to install $tool ${reset}\n"
        else
        echo -e "\n${magenta} [+] $tool is now installed ${reset}\n"
        fi
  else
    echo "${green} [*] $tool is already installed ${reset}"
    fi
done


#Installing remote-method-guesser
 if ! [ $(command -v "rmg.jar") ] > /dev/null; then
        echo -e "\n${cyan} [**] Remote-method-guesser is not installed. Installing now... ${reset}"
        sudo wget https://github.com/qtc-de/remote-method-guesser/releases/download/v4.3.1/rmg-4.3.1-jar-with-dependencies.jar -O /usr/local/bin/rmg.jar
        sudo chmod +x /usr/local/bin/rmg.jar
        if [ $? -ne 0 ]; then
            # catch and handle errors while installing
            echo -e "\n ${red}[-] Error: Failed to install remote-method-guesser ${reset}\n"
        else
        echo -e "\n${magenta} [+] Remote-method-guesser is now installed ${reset}\n"
        fi
  else
    echo "${green} [*] Remote-method-guesser is already installed ${reset}"
    fi

#Installing Beanshooter
 if ! [ $(command -v "beanshooter.jar") ] > /dev/null; then
        echo -e "\n${cyan} [**] Beanshooter is not installed. Installing now... ${reset}"
        sudo wget https://github.com/qtc-de/beanshooter/releases/download/v3.0.0/beanshooter-3.0.0-jar-with-dependencies.jar -O /usr/local/bin/beanshooter.jar
        sudo chmod +x /usr/local/bin/beanshooter.jar
        if [ $? -ne 0 ]; then
            # catch and handle errors while installing
            echo -e "\n ${red}[-] Error: Failed to install Beanshooter ${reset}\n"
        else
        echo -e "\n${magenta} [+] Beanshooter is now installed ${reset}\n"
        fi
  else
    echo "${green} [*] Beanshooter is already installed ${reset}"
    fi

#Installing etcdctl
 if ! [ $(command -v "etcdctl") ] > /dev/null; then
        echo -e "\n${cyan} [**] Etcdctl is not installed. Installing now... ${reset}"
        ETCD_VER=v3.4.23
        # choose either URL
        GOOGLE_URL=https://storage.googleapis.com/etcd
        #GITHUB_URL=https://github.com/etcd-io/etcd/releases/download
        DOWNLOAD_URL=${GOOGLE_URL}

        rm -f /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz
        rm -rf /tmp/etcd-download-test && mkdir -p /tmp/etcd-download-test

        curl -L ${DOWNLOAD_URL}/${ETCD_VER}/etcd-${ETCD_VER}-linux-amd64.tar.gz -o /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz
        tar xzvf /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz -C /tmp/etcd-download-test --strip-components=1
        rm -f /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz
        sudo mv /tmp/etcd-download-test/etcdctl /usr/local/bin/
        sudo mv /tmp/etcd-download-test/etcd /usr/local/bin/
        rm -rf /tmp/etcd-download-test/

        if [ $? -ne 0 ]; then
            # catch and handle errors while installing
            echo -e "\n ${red}[-] Error: Failed to install etcdctl ${reset}\n"
        else
        echo -e "\n${magenta} [+] etcdctl is now installed ${reset}\n"
        fi
  else
    echo "${green} [*] etcdctl is already installed ${reset}"
    fi

#Installing mongosh (MongoDB Shell)
 if ! [ $(command -v "mongosh") ] > /dev/null; then
        echo -e "\n${cyan} [**] mongosh is not installed. Installing now... ${reset}"
        curl -fsSL https://www.mongodb.org/static/pgp/server-7.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-7.0.gpg --dearmor
        echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu $(lsb_release -cs)/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
        sudo apt-get update -qq && sudo apt-get install -y mongodb-mongosh
        if [ $? -ne 0 ]; then
            echo -e "\n ${red}[-] Error: Failed to install mongosh ${reset}\n"
        else
        echo -e "\n${magenta} [+] mongosh is now installed ${reset}\n"
        fi
  else
    echo "${green} [*] mongosh is already installed ${reset}"
    fi

#Installing rdp-sec-check
 if ! [ $(command -v "rdp-sec-check") ] > /dev/null; then
        echo -e "\n${cyan} [**] rdp-sec-check is not installed. Installing now... ${reset}"
        sudo wget https://raw.githubusercontent.com/CiscoCXSecurity/rdp-sec-check/master/rdp-sec-check.pl -O /usr/local/bin/rdp-sec-check
        sudo chmod +x /usr/local/bin/rdp-sec-check
        if [ $? -ne 0 ]; then
            echo -e "\n ${red}[-] Error: Failed to install rdp-sec-check ${reset}\n"
        else
        echo -e "\n${magenta} [+] rdp-sec-check is now installed ${reset}\n"
        fi
  else
    echo "${green} [*] rdp-sec-check is already installed ${reset}"
    fi

echo -e "\n${green}########## Completed ########## ${reset} \n"
echo -e "\n${green} [*] All required tools have been checked and installed if necessary."


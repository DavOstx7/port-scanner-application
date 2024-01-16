#!/usr/bin/env bash
#This scripts execute commands by an arguements sent from the python script

case $1 in
	Privilege)
		echo "$(whoami)"
		[ "$UID" -eq 0 ] || exec sudo "$0" "$@"
		;;
	ScanForIPMAC) #Gets all of the online devices IP and MAC addresses in the format of: IP!!!MAC(NAME *if there is*)
		netmask=$(echo "$(hostname -I)" | sed 's/ /\/24/')
		sudo nmap -sn -n ${netmask} | awk -v x=$2 'BEGIN{a=0} /report for/ {printf $5; printf "!!!"} /MAC Address/ {for(i = 3; i < NF; i++) {printf $i " "}; print $NF; a+=1; if(a == x){exit 0}} END{print ""}'
		;;
	GetMyIP) #Gets this computer's ip address
		hostname -I | tr -d " \n"
		;;
	GetMyMAC) #Gets only the mac address of this pc (without the name)
                ifconfig | awk '$1 == "ether" {print $2}' | tr -d "\n"
                ;;
	DNSResolver) #Get's the devices name by sending a DNS query
		nslookup $2 | awk 'BEGIN{FS = "= "} $2!=""{print $2}' | tr -d '\n' | sed 's/.lan.//g'
		;;
	ScanDevice) #Performs an nmap scan with the parameters given
		scan_vars=$(echo "${@:2}") #Removing the first arguement which is ScanDevice (to keep the scan paramenters)
		sudo nmap ${scan_vars}
		;;
	OpenPorts) #Check's and returns the open (listening) ports on this computer
		sudo ss -tulpn | grep "LISTEN" | awk '{print $1, $5}' | awk -F "[ :]" 'NF == 3{print $1, $3}'
		;;
	KillProcess) #Kills a process related to a port resulting in closing the port
		sudo ss --kill state listening src :$2
		;;
	UFW) #Configures the firewall of ubuntu about ports
		ufw_vars=$(echo "${@:2}") #Removing the first arguement which is UFW
		sudo ufw ${ufw_vars}
		;;
	GetRouterMAC) #Gets the router's MAC address
		ip neigh|grep "$(ip -4 route list 0/0|head -1|cut -d' ' -f3) "|cut -d' ' -f5|tr '[a-f]' '[A-F]' | tr -d "\n"
		;;
	GetDATA) #Gets DATA out the text file. First var is the indicator for this, second variable is the the word that indicates the info. third variables is the file
		awk -v word="$2" 'BEGIN{a = "0"} {if(a == "1" && ($1 == ":" || $1 ~ /#/ || $1 == "\n")){exit 0} if(a == "1"){print} if($1 == ":" && $2 == word) {a = "1"}}' $3 | perl -p -e 'chomp if eof'
		;;
	ParseProtocol) #Parses the result of the nmap scan to only the protocol (and version)
		awk '/[0-9]+\/[a-zA-Z].*(open|filtered|open\|filtered)/{for(i = 3;i<=NF;i++){printf $i " "} printf "\n"}' TxtProj/help.txt | perl -p -e 'chomp if eof'
		;;
esac




#!/bin/bash
: '
Security Scanning Tool
======================
Requirements:
kali linux
skipfish.py in the same directory

'
# Global Script variables
Launcher="$0" # Script Path (Launcher should be in same directory)
ScriptDir=$(pwd "$Launcher") # Script Directory
Date=$(date +%m-%d-%Y) # Get Current Date
Time=$(date +%H_%M) # Get Current Time

# Project Variables if not defined run lookup_ip Function
auth_user="0"
auth_password=""
site="launch.papaginos.com" # URL without HTTP / HTTPS
ip="104.20.32.108" # External IP of WebApp / Website
internal_ip="" # Internal IP of server

url="https://$site" 

if [ $auth_user != 0 ]; then
	auth_short="$auth_user:$auth_password"
	Username="$auth_user"
	Password="$auth_password"
else
    auth_short=""
    Username=""
    Password=""
fi

function Logging() {
	if [ ! -d $LogDir ]; then
		echo "Creating $LogDir"
		mkdir -p $LogDir
	fi
	
	if [ -f $Log ]; then
		echo "Removing Old Log File"
		rm $Log
	fi
	#exec &> >(tee -a $Log) # Copy all output to Logfile
	#exec 2>&1 # Include Errors in Logfile
	
	echo " "
	echo " "
} # End of Logging Function


# Host Lookup Functions
# =====================================
# Search URL for IP Address
function url_host_ping() {
	echo "Getting Site's IP Address"
	echo "-------------------------------"
	echo "ping"
	ping $site -c 4 
	echo " "
} # End of URL_Ping Function

# Check URL for hostname
function url_host_nslookup() {
	echo "Looking up Hostname"
	echo "-------------------------------"
	echo "nslookup"
	nslookup $site
	echo " "
} # End of function URL_Host_nslookup

# (1)
function Host_Lookup() {
	: ' Host Lookup
	- Lookup Host Info Using URL
	======================================='
	Log="$LogDir/host-lookup.txt" && Logging; 
	url_host_ping 2>&1 | tee -a $Log # Get ip of URL
	url_host_nslookup 2>&1 | tee -a $Log # DNS Lookup of URL
} # End of Host_Lookup Function



# Inspect_Host Functions 
# =====================================
 # Check FQDN for various info
 function run_dmitry() {
	echo "------ DMITRY -----"
	echo "Running Deep Magic Inspection Tool"
	command="dmitry -winsepfb -o $LogDir/dmitry.txt  $url"
	echo "$command"
	eval $command
	echo " "
} # End of function URL_dmitry

# Check FQDN for load balancer
function loadbalance_detector() {
	echo "------ Load Balance Detector ------"
	echo " "
	command="lbd $site"
	echo "$command"
	eval $command
	echo " "
} # End of function Load_Balance_Detector

# Checks URL for web application firewall
function web_app_firewall_check() {
	echo "------ WAFW00F -----"
	echo "Checking for Web Application Firewall"
	command="wafw00f -av $url"
	echo "$command"
	eval $command
	echo " "
} # End of function Web_App_Firewall_check

function ssl_scan() {
	echo "------ SSL Scan ------"
	command="sslscan https://$site:443"
	echo "$command"
	eval $command
	echo " "
} # End of ssl_scan function


# (2)
function Inspect_Host() {
	: ' Inspect Host
	- Performs additional lookups with FQDN and url
	======================================='
	Log="$LogDir/dmitry-log.txt" && Logging;
	run_dmitry 2>&1 | tee -a $Log; # perform various lookups of FQDN of host

	Log="$LogDir/LoadBalancer_Check.txt" && Logging;
	loadbalance_detector 2>&1 | tee -a $Log; # Checks for Load Balancer

	Log="$LogDir/Firewall_Check.txt" && Logging;
	web_app_firewall_check 2>&1 | tee -a $Log;  # Checks for Web App Firewall
	
	Log="$LogDir/ssl.txt" && Logging; 
	ssl_scan 2>&1 | tee -a $Log; # Checks SSL Cert if HTTPS. Can Detect Heartbleed vulnerability
} # End of Inspect_Host Function



# DNS Lookup Functions
# =====================================
# Get DNS Information from Web Application
function dns_recon() {
	echo "-------- DNS Recon ------"
	command="dnsrecon -d $site"
	echo "$command"
	eval $command
	echo " "
} # End of dns_recon Function

function dns_dig() {
	echo "-------- DIG ----------"
	command="dig $site ANY +noall +answer"
	echo "$command"
	eval $command
	echo " "
	echo "Running Trace:"
	command="dig $site +trace"
	eval $command
	echo " "
} # End of dns_dig Function

function dns_fierce() {
	echo "-------- Fierce ------"
	command="fierce -dns $site"
	echo "$command"
	eval $command
	echo " "
} # End of dns_fierce Function

function dns_tracer() {
	echo "-------- DNS Tracer ------"
	command="dnstracer -co $site"
	echo "$command"
	eval $command
	echo " "
} # End of dns_tracer Function

# (3)
function DNS_Lookup() {
	Log="$LogDir/dnslookup.txt" && Logging; 
	echo "Performing DNS Lookup"
	echo "===================="
	dns_recon 2>&1 | tee -a $Log
	dns_dig 2>&1 | tee -a $Log
} # End of DNS_Lookup function



# Port Scan Function
# =====================================
# Scan for Open TCP and UDP Ports on target IP and URL
function Port_Scan() {
	echo "Scanning Ports"
	echo "--------- NMAP --------"
	# Run NMap -vv (verbose) -AO (OS Detection) and -Pn (Bypass host reply)
	command="nmap -v -AO -Pn $ip"
	# command="nmap -vv -AO -Pn $site"
	echo "$command"
	eval $command
	echo " "
	echo "TCP and UDP Scan"
	echo "---------------------"
	# TCP (-sT) and UDP (-sU)
	command="nmap -v -sU -sT $ip" 
	# command="nmap -vv -sU -sT $site" 
	echo "$command"
	eval $command
} # End of Port_Scan function



# Site Crawl Function
# =====================================
# Crawl the Website / Application to get a list of URLs
function Crawl_Site() {
	Logging;
	echo "Web Application Site Crawl"
	echo " "
	echo "------- SkipFish --------"
	command="python ./skipfish.py $site $auth_short"
	echo "$command"
	eval $command
	echo " "
} # End of Crawl_Site function



# Web App Vulnerability Scanning Functions
# =====================================
# Scan the Website / Application for Vulnerabilities

function run_uniscan() {
	echo "------- Uniscan --------"
	command="uniscan -u $url -qweds"
	echo "$command"
	eval $command
	cp /usr/share/uniscan/report/*$site*.html $LogDir/sitemap/
	echo " "
} # End of uniscan function

# dotdotpwn with auth
function ddp_auth() {
	echo "------- dotdotpwn --------"
	command="dotdotpwn.pl -m http -U $Username -P $Password -h $url -M GET -S -O"
	echo "$command"
	eval $command
	echo " "
} # End of ddp_auth function

function ddp() {
	echo "------- dotdotpwn --------"
	command="dotdotpwn.pl -m http -h $url -M GET -S -O"
	echo "$command"
	eval $command
	echo " "
} # End of ddp function

function run_nikto() {
	echo "------- Nikto --------"
	command="nikto -host $url -no404 -o $LogDir/nikto-output.txt"
	echo "$command"
	eval $command
	echo " "
} # End of nikto function

# Parent Function for Web Application Vulnerability Scanning
function Web_Vulnerability_Scan() {
	echo " "
	echo "Web Application Vulnerability Scan"
	echo "----------------------------------"
	echo " "
	Log="$LogDir/uniscan.txt" && Logging;
	run_uniscan 2>&1 | tee -a $Log; # Run uniscan function
	
	Log="$LogDir/nikto.txt" && Logging;
	run_nikto 2>&1 | tee -a $Log; # Runs the nikto function
	
	if [ $auth_user != 0 ]
	then
		Log="$LogDir/dotdotpwn.txt" && Logging;
		ddp_auth 2>&1 | tee -a $Log; # Runs dotdotpwn function with authentication
	else
		Log="$LogDir/dotdotpwn.txt" && Logging;
		ddp 2>&1 | tee -a $Log; # Runs dotdotpwn function without authentication
	fi
	echo " "
} # End of Web_Vulnerability_Scan function


LogDir="$ScriptDir/reports/lookup"
#Host_Lookup; # Run Host_Lookup Function (1)
#Inspect_Host; # Run Inspect_Host Function (2)
#DNS_Lookup; # Performs DNS lookup using FQDN (3)

LogDir="$ScriptDir/reports/scan"
#Log="$LogDir/portscan.txt" && Logging; # Creates Logging Directory and Removes Previous Existing File
#Port_Scan 2>&1 | tee $Log; # Performs a portscan using FQDN of host

LogDir="$ScriptDir/reports/sitemap"
#Log="$LogDir/site-crawl.txt" && Logging; # Creates Logging Directory and Removes Previous Existing File
#Crawl_Site 2>&1 | tee $Log; # Performs a python sitemap of url

LogDir="$ScriptDir/reports/scan"
Web_Vulnerability_Scan; # Performs various web application vulnerability scans


"""
Author: GrimmVenom <grimmvenom@gmail.com>
Summary:
	Script to perform active information gathering for a penetration test
	Designed to be ran on Kali linux, which has other 3rd party tools that will be leveraged

Resources:
	https://xael.org/pages/python-nmap-en.html
	https://www.studytonight.com/network-programming-in-python/integrating-port-scanner-with-nmap
	https://couchdb-python.readthedocs.io/en/latest/client.html
"""

import nmap
import argparse, time, os, sys, itertools, json
from datetime import datetime
import requests, socket, ipaddress
from netifaces import interfaces, ifaddresses, AF_INET
import couchdb
from uuid import uuid4

# ToDO:
# SMB Enum
# FTP
# SMTP ENum
# OS + Service Vulnerability Mapping


def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', "--target", action='append', dest='ips', help='-t <target IP>')
	parser.add_argument('-q', '--query', action='store', dest='nmap_query', default="basic", help='--query basic, advanced, Full, or <custom nmap flags>')
	parser.add_argument('-o', '--output', action='store', dest='output_dir', help='--output <path to output directory>')
	parser.add_argument('-db', '--database',  action='store', dest='database', help='-db "table"')
	arguments = parser.parse_args()
	arguments.targets = list()
	
	if arguments.ips:
		for target in arguments.ips:
			try:
				if "-" in target:  # Determine IPs in Range
					base_ip = '.'.join(target.split('-')[0].split('.')[0:3])
					arguments.start = target.split('-')[0]
					arguments.end = base_ip + "." + target.split('-')[1]
				
					if arguments.start and arguments.end:
						print("\nIP Range Specified\n==========================")
						print("Start: \t", arguments.start)
						print("End: \t", arguments.end)
						print("\n")
						for ip in range(int(ipaddress.IPv4Address(arguments.start)), int(ipaddress.IPv4Address(arguments.end))):
							ip = ipaddress.IPv4Address(int(ip))
							arguments.targets.append(str(ip))
			
				elif "/" in target: # Determine IPs in CIDR
					print("\nIP CIDR Range Specified for ", str(target), "\n==========================")
					for scoped_ip in ipaddress.IPv4Network(target):  # Loop through IP Addresses in Network
						arguments.targets.append(str(scoped_ip))
					print("# of Targets: ", str(len(arguments.targets)))
					print("\n\n")
				else:
					arguments.targets.append(target)
			except Exception as e:
				print(e)
				pass
	
	if len(arguments.targets) < 1:
		parser.error("must specify target, file with targets, start & end, or network to determine IPs to target")
	
	arguments.targets = set(arguments.targets)
	tempips = [socket.inet_aton(ip) for ip in arguments.targets]
	tempips.sort()
	arguments.targets = [socket.inet_ntoa(ip) for ip in tempips]
	print("\nTargets:\n==========================")
	print(arguments.targets)
	print("\n\n")
	
	return arguments


class ActiveRecon:
	def __init__(self):
		self.arguments = get_arguments()
		self.current_directory = os.path.dirname(os.path.realpath(__file__))
		self.date = "date_" + str(time.strftime("%Y_%m_%d"))
		if not self.arguments.output_dir:
			self.arguments.output_dir = self.current_directory + os.sep + 'results'
			if not os.path.exists(self.arguments.output_dir):
				print("Creating: " + str(self.arguments.output_dir))
				os.makedirs(self.arguments.output_dir)
		if not self.arguments.database:
			self.arguments.database = self.date
		self.ping_args = '-n -Pn -v -sn'
		# self.ping_args = '-n -Pn -v -sT -p 21,23,80,443,139,445,3389'
		self.basic_args = '-n -Pn -v -O -sV -sT --top-ports 200 --script=banner-plus,smb-os-discovery'
		self.advanced_args = '-n -Pn -v -O -sV -sT -sU --top-ports 300 --script=banner-plus,smb-os-discovery'
		self.full_args = '-n -Pn -v -O -sV -sT -sU -p0-65535 --script=banner-plus,smb-os-discovery'
		self.scan_type = str()
		self.local_data = self.get_local_info()  # Get Attacking Machine Information
		self.async_scan = nmap.PortScannerAsync()
		self.ping_results = dict()
		self.basic_results = dict()
	
	def get_local_info(self):
		print("Checking Attacker (Local) Machine Info")
		local_data = dict()
		try:
			host_name = socket.gethostname()
			local_data['HostName'] = host_name
		
		# print("Hostname :  ", host_name)
		# print("Local IP : ", host_ip)
		except Exception as e:
			print(e)
			print("Unable to get Hostname")
			host_name = "N/A"
			pass
		
		try:
			# IPAddr = socket.gethostbyname(socket.gethostname())
			"""
			IPAddr = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] \
				if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)),
				s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET,
				socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
			"""
			IPAddr = [ifaddresses(face)[AF_INET][0]["addr"] for face in interfaces() if AF_INET in ifaddresses(face)]
			local_data['IP_Address'] = IPAddr
		except Exception as e:
			print("Unable to find local IP")
			print(e)
			IPAddr = None
			pass
		
		try:
			external_ip = requests.get('https://api.ipify.org').text
			local_data['External_IP_Address'] = external_ip
		except Exception as e:
			print("Unable to find external IP")
			print(e)
			external_ip = None
			pass
		
		print("\nLocal Machine Info:\n============================")
		print("HostName: \t\t" + host_name)
		print("External IP: \t\t" + external_ip)
		print("Local IP: \t\t" + str(IPAddr))
		print("\n\n")
		return local_data
	
	def nmap_ping_sweep(self, target):
		print("Performing Quick Ping Sweep on: ", str(target), "\n------------------")
		nm = nmap.PortScanner()
		nm.scan(hosts=target, arguments=self.ping_args)
		hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
		for host, status in hosts_list:
			# std = str('{0}:{1}'.host)
			# print(host, status)
			print("Host: ", str(host), " Status: ", str(status))
			self.ping_results[str(host)] = str(status)
	
	def main(self):
		if self.arguments.nmap_query == "basic":
			self.scan_type = "basic"
			self.nmap_async(self.basic_args)
			"""  # Uncomment for ping scans + individual nmap scans
			for target in self.arguments.targets:
				self.nmap_ping_sweep(target)
				if self.ping_results[target] == 'up':
					self.basic(target)
				else:
					print("Target did not appear to be online")
			self.results_to_couchdb(self.basic_results)  # add Results to CouchDB """
		elif self.arguments.nmap_query == "advanced":
			self.scan_type = "advanced"
			self.nmap_async(self.advanced_args)
		elif self.arguments.nmap_query == "full":
			self.scan_type = "full"
			self.nmap_async(self.full_args)
		else:
			self.scan_type = "custom"
			self.nmap_async(str(self.arguments.nmap_query))
	
	def basic(self, target):  # Scans / Parses Results from a single target at a time
		OS = dict()
		tcp_results = dict()
		udp_results = dict()
		closed_ports = dict()
		closed_ports["tcp"] = dict()
		closed_ports["udp"] = dict()
		open_ports = dict()
		open_ports["tcp"] = dict()
		open_ports["udp"] = dict()
		print("\nPerforming Basic NMap Scan on: ", target, "\n\n")
		nm = nmap.PortScanner()
		nm.scan(hosts=target, arguments=self.basic_args)
		
		count = 0
		for item in nm[target]['osmatch'][0:3]:
			count += 1
			if str(count) not in OS.keys():
				OS[str(count)] = dict()
				OS[str(count)]['name'] = str(item['name'])
				OS[str(count)]['type'] = str(item['osclass'][0]['type'])
				OS[str(count)]['vendor'] = str(item['osclass'][0]['vendor'])
				OS[str(count)]['osfamily'] = str(item['osclass'][0]['osfamily'])
				OS[str(count)]['osgen'] = str(item['osclass'][0]['osgen'])
				OS[str(count)]['version'] = str(item['osclass'][0]['cpe'][0]).replace('cpe:/0:', '')
		
		if target not in self.basic_results.keys():
			self.basic_results[target] = dict()
		if 'Results' not in self.basic_results[target].keys():
			self.basic_results[target]["Results"] = dict()
			
		if "OS" not in self.basic_results[target].keys():
			self.basic_results[target]["OS"] = OS
			
		if "Command" not in self.basic_results[target].keys():
			self.basic_results[target]["Command"] = str(nm.command_line())
			
		if "Scan_Info" not in self.basic_results[target].keys():
			self.basic_results[target]["Scan_Info"] = dict()
			try:
				scan_info = nm.scaninfo()
				self.basic_results[target]["Scan_Info"]["tcp"] = scan_info["tcp"]["services"].split(',')
			except:
				pass
			try:
				scan_info = nm.scaninfo()
				self.basic_results[target]["Scan_Info"]["udp"] = scan_info["udp"]["services"].split(',')
			except:
				pass
			self.basic_results[target]["Scan_Info"]["stats"] = nm.scanstats()
			self.basic_results[target]["Scan_Info"]["stats"]["status"] = nm[target]["status"]
		
		if "Auditor_Info" not in self.basic_results:
			self.basic_results["Auditor_Info"] = self.local_data
		
		if 'tcp' in nm[target].keys():
			tcp_results = nm[target]['tcp']
			for port, result in tcp_results.items():
				if (result['state'] in ["closed", "filtered"]) or (result["reason"] == "conn-refused"):
					if str(port) not in closed_ports["tcp"].keys():
						closed_ports["tcp"][str(port)] = dict()
					closed_ports["tcp"][str(port)] = result
				else:
					if str(port) not in open_ports["tcp"].keys():
						open_ports["tcp"][str(port)] = dict()
					open_ports["tcp"][str(port)] = result
			if "tcp" not in self.basic_results[target]["Results"].keys():
				self.basic_results[target]["Results"]["tcp"] = dict()
				self.basic_results[target]["Results"]["tcp"]["open"] = dict()
				self.basic_results[target]["Results"]["tcp"]["closed"] = dict()
			self.basic_results[target]["Results"]["tcp"]["open"] = open_ports["tcp"]
			self.basic_results[target]["Results"]["tcp"]["closed"] = closed_ports["tcp"]
		
		if 'udp' in nm[target].keys():
			udp_results = nm[target]['udp']
			for port, result in udp_results.items():
				if (result['state'] in ["closed", "filtered"]) or (result["reason"] == "conn-refused"):
					if str(port) not in closed_ports["udp"].keys():
						closed_ports["udp"][str(port)] = dict()
					closed_ports["udp"][str(port)] = result
				else:
					if str(port) not in open_ports["udp"].keys():
						open_ports["udp"][str(port)] = dict()
					open_ports["udp"][str(port)] = result
			if "udp" not in self.basic_results[target]["Results"].keys():
				self.basic_results[target]["Results"]["udp"] = dict()
				self.basic_results[target]["Results"]["udp"]["open"] = dict()
				self.basic_results[target]["Results"]["udp"]["closed"] = dict()
			self.basic_results[target]["Results"]["udp"]["open"] = open_ports["udp"]
			self.basic_results[target]["Results"]["udp"]["closed"] = closed_ports["udp"]
			
		output_file = self.arguments.output_dir + os.sep + self.scan_type + "_" + str(target) + '.json'
		print("Output File: ", str(output_file))
		with open(output_file, 'w') as outfile:
			outfile.write(json.dumps(self.basic_results, indent=4, sort_keys=True))
			outfile.close()
		# print(json.dumps(self.basic_results, indent=4, sort_keys=True))
	
	def callback_result(self, host, scan_results):
		basic_results = dict()
		print('------------------')
		print("Target: ", host, "\n")
		parsed = json.loads(json.dumps(scan_results))
		# print(json.dumps(parsed, indent=4, sort_keys=True))
		nmap_results = scan_results['nmap']
		results = scan_results['scan']
		
		if scan_results:
			output_file = self.arguments.output_dir + os.sep + "advanced_" + str(host) + '.json'
			print("Output File: ", str(output_file))
			with open(output_file, 'w') as outfile:
				outfile.write(json.dumps(parsed, indent=4, sort_keys=True))
				outfile.close()
			self.results_to_couchdb(scan_results)
	
	def nmap_async(self, query):  # Perform Full scan and attempt to get host info such as hostname and OS, Caution! Will take a long time to execute
		targets = str(','.join(map(str, self.arguments.targets)))
		print("\nPerforming NMap Scan on: ", targets)
		start = time.time()
		self.async_scan.scan(hosts=targets, arguments=str(query), callback=self.callback_result)
		
		spinner = itertools.cycle(['-', '/', '|', '\\'])
		while self.async_scan.still_scanning():
			end = time.time()
			sys.stdout.write('[%s] %s \r' % (spinner.__next__(), round(end - start, 2)))  # write the next character
			sys.stdout.flush()  # flush stdout buffer (actual character display)
			sys.stdout.write('\b')  # erase the last written char
		print("\n")
		self.async_scan.wait(2)  # you can do whatever you want but I choose to wait after the end of the scan
		# self.async_scan.stop()
	
	def results_to_couchdb(self, data):
		print("Parsing Results to database")
		try:
			server = couchdb.Server()
			if not self.arguments.database in server:
				server.create(self.arguments.database)
			db = server[self.arguments.database]
			doc_id = uuid4().hex
			print("UUID: ", doc_id)
			db[doc_id] = data
		except Exception as e:
			print(e)
			pass
		

if __name__ == "__main__":
	ActiveRecon = ActiveRecon()
	ActiveRecon.main()

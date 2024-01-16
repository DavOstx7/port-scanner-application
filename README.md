# port-scanner-application

This is an old Port Scanner Application written in python ;)

## Prerequisites

1) Requires running on Ubuntu.
2) Requires nmap installed: `sudo apt install nmap`.
3) Make the terminal script executable: `chmod +x ./Terminal.sh`.

## Files

* `main.py` - The main program which starts up the port scanner application in GUI mode.
* `guicontrol.py` - This module is responsible for customized GUI elements.
* `cbcontrol.py` - This module is responsible for extra functionality on checkbutton elements.
* `portcontrol.py` - This module is responsible for operating ports and network traffic through GUI.
* `peer2peer.py` - This module is responsible for communicating with other instances of the Application.
* `TxtProj/*` - The text files that the application loads and uses in runtime.
* `PicProj/*` - The ping (icons) files that application loads and displays in runtime.


**__NOTE:__** This code was from my highschool's finals project. It is very ugly and should be refactored!
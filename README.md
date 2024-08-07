# Port Scanner Application

This is an old Port Scanner Application written in Python ;)

**__NOTE:__** This code was from my highschool's finals project. It does not follow SOLID principles whatsoever, and
should definitely be refactored!

## Prerequisites

1) Requires running on Ubuntu.
2) Requires nmap installed: `sudo apt install nmap`.
3) Requires to make the Terminal shell script executable: `chmod +x ./Terminal.sh`.

## Files

* `main.py` - The main program which starts up the port scanner application in GUI mode.
* `guicontrol.py` - This module is responsible for customized GUI elements.
* `cbcontrol.py` - This module is responsible for extra functionality on checkbutton elements.
* `portcontrol.py` - This module is responsible for operating ports and network traffic through GUI.
* `peer2peer.py` - This module is responsible for communicating with other instances of the Application.
* `TxtProj/*` - The .txt files that the application loads and uses in runtime.
* `PicProj/*` - The .png (icon) files that the application loads and displays in runtime.
* `Examples/*` - Some example images that show the capabilities and features of the port scanner!

## Running

```shell
python3 main.py # You may need to run this with sudo if there is insufficient permissions
```

## Examples

### Application

<img src="./Examples/app.png">

---

### Port Control

<img src="./Examples/port-control.png">

---

### Ready Made Scans + Settings

<img src="./Examples/ready-scans.png">

---

### Custom Made Scans

<img src="./Examples/custom-scan-1.png">

---

### Main Output Box

<img src="./Examples/main-box.png">

---

### View Messages

<img src="./Examples/recv-msg.png">

---

### Message Peer

<img src="./Examples/send-msg.png">

---

**__NOTE:__** More example images exist under the [Examples](Examples) directory.

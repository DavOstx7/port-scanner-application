#!/usr/bin/env python3
# ~~~~~imports~~~~~#
from functools import partial
from tkinter import *
import sys
import logging
import os
import os.path
import subprocess
from PIL import Image, ImageTk
from tkinter import messagebox
import time
from datetime import datetime
import threading
import re
from googlesearch import search
import webbrowser
# ~~~~~~~~~~~~~~~~~#

# ~~~~~classes~~~~~#
from guicontrol import ScrollableFrameH, VerticalScrolledFrame, ScrollableTextBox, HyperlinkManager
from portcontrol import PortControl
from cbcontrol import MyCheckButton, SharedLog
from peer2peer import Peer


# ~~~~~~~~~~~~~~~~~#

# ~~~~~functions~~~~~#
def ReturnDATA(word, filename):
    """This functions uses the bash script to return a specific data from a textfile"""

    try:
        return subprocess.check_output(f'./Terminal.sh GetDATA {word} {filename}', shell=True).decode('utf-8')
    except:
        messagebox.showwarning("PROBLEM", "Cannot show info, make sure that no files are missing!")


def ShowINFO(title, word):
    """Creates a popup with the info (good for short info)"""

    try:
        messagebox.showinfo(title, ReturnDATA(word, "./TxtProj/INFO.txt"))
    except:
        messagebox.showwarning("PROBLEM", "Cannot show info, make sure that no files are missing!")


def ShowCustomINFO(title, word, size):
    """Creates a popup with textbox (good for long info)"""

    try:
        top = Toplevel(root)
        top.title(title)
        if (size == "big"):
            if (SCREEN_SIZE == "fullscreen"):
                top.attributes('-zoomed', True)  # Make the INFO window fullscreen
            else:
                top.geometry(SCREEN_SIZE)
        else:
            top.geometry('1150x500')
        x = ScrollableTextBox(top)
        textbox = x.textbox
        textbox.insert(END, ReturnDATA(word, "./TxtProj/INFO.txt"))
    except:
        messagebox.showwarning("PROBLEM", "Cannot show info, make sure that no files are missing!")


def CreateNewDevice(ip, name, image, mac):
    """This function creates a new Device Box on screen"""

    global column_scroll  # The column of the next checkbutton
    global peer
    cb = MyCheckButton(frame.scrollable_frame, peer)  # Making the Custom Checkbutton
    cb.set_values(root, my_mac, ip=ip, name=name, connection="CONNECTED", mac=mac)  # Setting ip, name, connection
    if (Conn_Var.get() == 1):
        cb.add_to_log(f'{cb.connection}')  # Adding to the log the time and connection state  of the new IP address
    cb.config(text=f'{cb.ip}\n{cb.name}\n{cb.mac}\n{cb.connection}', image=image, compound='top', variable=cb.status,
              onvalue='1', offvalue='0', fg=GREEN,
              activeforeground=GREEN)  # A check button with pc icon and ip+name+connection of the device
    if (mac == my_mac):  # Make sure to let the user know which device is his
        cb.config(fg="black", activeforeground="black")  # Changing the color of the text
    if (ip == localhost):  # Make sure to to let the user easily see his localhost checkbutton
        cb.config(fg=ORANGE, activeforeground=ORANGE, text=f'{localhost}\nlocalhost\n')
    if (mac == router_mac):  # Make sure to let the user know this mac is of his router
        cb.config(text=f'{cb.ip}\n{cb.name} *ROUTER*\n{cb.mac}\n{cb.connection}')

    cb.deselect()  # Remove the auto select (tkinter bug)
    cb.grid(row=0, column=column_scroll, sticky='nsew')  # Putting the checkbutton on screen
    cb.OptionsButton(frame.scrollable_frame, 1, column_scroll)  # Making a log button at the bottom of the frame
    cb_list.append(cb)  # Adding the Checkbutton to the list
    column_scroll += 1  # Adding 1 to the next column indicator
    ip_list.append(ip)  # Adding IP to the ip_list(connected/disconnected)
    mac_list.append(mac)  # Adding the MAC to the mac_list(connected/disconnected)


def IsPhone(device):
    """This function checks if a device is likely a phone - if yes returns True, else returns False"""

    if (device == ''):
        return False
    for phone in phones_list:
        if (phone.lower() in device.lower()):
            return True
    return False


def GetDeviceByMAC(mac):
    """This returns the checkbutton of the ip given"""

    for cb in cb_list:  # Run on every checkbutton
        if (cb.mac == mac):  # If the checkbutton has the ip, return it
            return cb


def IsMacIn(mac, lst):
    """Checks if the mac address is in one of the tuples in the list"""

    for x in lst:
        if (x[1] == mac):
            return True
    return False


def DevicesOnScreen():
    """This function manages the Checkbutton of different devices shown on screen"""

    is_err1 = False
    is_err2 = False

    while True:
        try:
            lock.acquire()
            global cb_list  # The list to store the checkboxes
            global ip_list  # List of the IP's which were connected before
            global column_scroll  # The column of the next checkbutton
            global mac_list  # All the mac addresses which were connected before
            global peer

            x = ""
            x = ReturnDATA("MAX_DEVICE",
                           "./TxtProj/CONFIG.txt")  # x contains the maximum amount of the devices to be found online in the scan
            if (x.isdigit() == False):
                x = 100  # Max amount in my opinion

            ipmac_result = subprocess.check_output(f'./Terminal.sh ScanForIPMAC {x}', shell=True).decode(
                'utf-8')  # Getting all the online devices IP's (online/connected at this moment)
            ipmac_online = ipmac_result.splitlines()  # Splitting the IP's to a list

            if (len(ipmac_online) == 1 and is_err1 == False and 'normal' == root.state()):
                messagebox.showwarning("PROBLEM",
                                       "Cannot Update And Show Other Devices!, Try Checking Your Internet Connection\n\n*This Message Is Only Shown Once!*")
                is_err1 = True

            ipmac_online.pop()  # The last element is this user's PC, which we will add manualy.
            online_data = []  # List to contain tuple's of (IP, MAC, MAC-NAME)

            for x in ipmac_online:
                ip = x.split("!!!")[0]
                mac_and_name = x.split("!!!")[1]
                mac = mac_and_name.split(" ")[0]
                mac_name = mac_and_name.split(" ", 1)[1]
                mac_name = mac_name[1:-1]  # Remove the "()" at the start and end of the string
                online_data.append((ip, mac, mac_name))

            if (wait_label.winfo_exists() == 1):  # If the wait_label is alive
                wait_label.destroy()  # Destroy the wait_label

            my_ip = subprocess.check_output('./Terminal.sh GetMyIP', shell=True).decode('utf-8')  # Gets the user's ip
            if (len(ip_list) == 0):  # Scan just started - add localhost and this user's data
                shared_log = SharedLog(frame.scrollable_frame, log_img, root, peer)
                shared_log.build()
                shared_log.start()
                column_scroll = 1
                CreateNewDevice(localhost, "localhost", pc_img, '')  # Local host checkbutton
                CreateNewDevice(my_ip, 'My Computer', pc_img, my_mac)  # This user's checkbutton

            for cb in cb_list:  # Running on every device that was connected before
                mac = cb.mac  # Getting the ip of the device
                # We only need to do something if the device is disconnected (if he is still connected we don't have to do anything) and he hasn't been updated yet
                if (IsMacIn(mac,
                            online_data) == False and cb.connection != 'DISCONNECTED' and mac != '' and mac != my_mac):  # This MAC is not connected anymore to the LAN network AND hasn't been updated yet and isn't the localhost (only localhost's mac is '').
                    cb.connection = 'DISCONNECTED'  # Updating his connection
                    cb.config(fg=RED, activeforeground=RED)  # Updating the color
                    cb.update_text()  # Updating the test
                    if (Conn_Var.get() == 1):
                        cb.add_to_log('DISCONNECTED')  # Updating the log

            for x in online_data:  # Running on every device's MAC that's currently conncted to the LAN network
                ip = x[0]
                mac = x[1]
                mac_name = x[2]
                cb = GetDeviceByMAC(mac)  # Get the checkbutton that has this MAC address

                if (mac not in mac_list):  # New connection from this MAC address - he was never connected
                    name = subprocess.check_output(f'./Terminal.sh DNSResolver {ip}', shell=True).decode(
                        'utf-8')  # Getting the name of the new device's IP via nslookup
                    if (name == ''):  # If didn't get a name via ns lookup, try the mac's name
                        name = mac_name
                    if (IsPhone(name)):  # Checking if the device is most likely a phone
                        image = phone_img
                    elif (mac == router_mac):
                        image = router_img
                    else:
                        image = pc_img
                    CreateNewDevice(ip, name, image, mac)  # Creating a new device on screen in the scrollable frame
                else:  # This device either reconnected (was connected in the past) or still connected (he is not a new connection)
                    # We only need to do something if the device is reconnecting ===> before this he was disconnected (if the device is still connected we dont have to update anything) and it's not the loop ack address
                    if (
                            cb.connection == 'DISCONNECTED' and ip != localhost and mac != my_mac):  # if its the localhost/our computer  we don't need to update it.
                        cb.connection = 'CONNECTED'  # Updating his connection
                        cb.config(fg=GREEN, activeforeground=GREEN)  # Updating his color
                        if (Conn_Var.get() == 1):
                            cb.add_to_log(f'RECONNECTED')  # Updating the log
                    if (cb.ip != ip):  # Update the ip of the device in case it has changed
                        if (Conn_Var.get() == 1):
                            cb.add_to_log(f'IP changed from {cb.ip} to {ip}')
                        if (cb.ip == my_ip):
                            my_ip = ip
                            peer.my_ip = ip
                        cb.ip = ip

                    cb.update_text()  # need to update the text in case ip changed or he reconnected

            lock.release()
            time.sleep(SLEEP_THREAD)
        except:
            if ('normal' == root.state() and is_err2 == False):
                messagebox.showwarning("ERROR",
                                       "There Is A Problem In Managing The Devices On The Screen...\n\n*This Message Is Only Shown Once!*")
                is_err2 = True


def CreateOption(port_entry, time_template_var, tcp_teq_var, flags_list, USC_list, payload_entry, options_list):
    """This function creates the option (proper use of nmap in terminal form) for the scan (putting all of the paramaters that the user chose into one option)"""
    """This function will not check for complex syntax since there could be too many checks, that nmap does anyway..."""

    option = ""  # Will append to this string each time parameters of the scan that the user chose

    ports_specified = port_entry.get().lower()  # Gets what's in the port entry
    # Checking the syntax + adding it to the option
    if (ports_specified.isspace() == False and ports_specified != ""):
        if (ports_specified == "fast"):
            option += "-F "
        elif (ports_specified == "all"):
            option += "-p- "
        elif ("exclude" in ports_specified):
            x = ports_specified.split(" ")
            if (len(x) != 2):
                textbox.insert(END,
                               f'You entered bad syntax for the port specification!\n"{ports_sepcified}" is not valid')
            else:
                port_range = x[1]
                option += f'--exclude-ports {port_range} '
        else:
            option += f'-p {ports_specified} '

    # Gets the selected time template radiobutton + checks the syntax and adds it to the option
    time_template = time_template_var.get()
    if (time_template != " " and time_template != "default"):
        option += f'{time_template} '

    # Gets the selected tcp technique radio button + checks the syntax and adds it to the option
    tcp_teq = tcp_teq_var.get()
    if (tcp_teq != " " and tcp_teq != "default"):
        option += f'{tcp_teq} '

    # Loops through the checkbuttons of the TCP flags and adds them to the option
    s = ""
    for cb, var in flags_list:
        s += var.get()
    if (s != ""):
        option += f'--scanflags {s} '

    # Loops through the checkbuttons of the UDP/SCTP techniques + check syntax and adds them to the option
    s = ""
    for cb, var in USC_list:
        s = var.get()
        if (s != ""):
            option += f'{s} '

    # Gets what's in the ASCII string entry + checks syntax and adds it to the option
    data_string = payload_entry.get()
    if (data_string != ""):
        option += f"--data-string '{data_string}' "

    # Loops through the checkbuttons of the advanced options + checks syntax and adds them to the option
    s = ""
    for cb, var in options_list:
        s = var.get()
        if (s != ""):
            option += f'{s} '
    print(option)

    Scan(option)  # Sends to the scan function the scan with the option (option = all of the scan parameters)


def OpenLink(link):
    """Opening a given link"""

    webbrowser.open(link)


def Scan(option):
    """This function scans all of the selected devices according to the option (scan paramters)"""

    textbox.insert(END, "Activating this scan: sudo nmap " + option + " <ip> \n\n")
    for cb in cb_list:  # Loops through each MyCheckButton Object which tells us which devices have been selected to scan
        status = cb.status.get()
        if (status == '' or status == '0'):  # Device has not been selected
            continue
        try:
            x = timeout_e.get()
            if (x.isdigit()):  # If there is a timeout in the GUI, make the subprocess with a timeout
                output = subprocess.check_output(f'./Terminal.sh ScanDevice {option} {cb.ip}', shell=True,
                                                 timeout=int(x)).decode(
                    'utf-8')  # Sends to the Terminal.sh the scan and it activates
            else:
                output = subprocess.check_output(f'./Terminal.sh ScanDevice {option} {cb.ip}', shell=True).decode(
                    'utf-8')  # Sends to the Terminal.sh the scan and it activates
            if (Log_Var.get() == 1):  # If the log checkbutton is selected, add the result to the log file
                cb.add_to_log(
                    f'\n\n----------SCAN RESULT----------\nScan activated: {option}\n{output}\n-------------------------------\n')
            textbox.insert(END, output + "\n")
            if (
                    Vuln_Var.get() == 1):  # If the vulnerability checkbutton is selected, adding links for a general search in the database of CVE website
                f = open("TxtProj/help.txt", "a")  # Creating a temporarily file with the output
                f.write(output)
                f.close()
                p = subprocess.check_output(f'./Terminal.sh ParseProtocol; rm TxtProj/help.txt', shell=True).decode(
                    'utf-8')  # . #Sends to the Terminal.sh the scan and it activates the parsing to find only the protocol and then deletes the file
                if (p == ""):  # No protocols were found
                    textbox.insert(END, "There are no protocols or versions to search for vulnerabilities!" + "\n")
                    continue
                protocol_list = p.splitlines()
                for protocol in protocol_list:  # Going through each protocol and giving a link
                    textbox.insert(END, f'Possible vulnerabilities for {protocol} --> ')
                    textbox.insert(END, f'open link', hyperlink.add(
                        partial(OpenLink, f'https://www.cvedetails.com/google-search-results.php?q={protocol}')))
                    textbox.insert(END, "\n")
        except:  # Bad syntax enetered
            textbox.insert(END,
                           "An error has been occurred. 1) try checking for typos! 2) try checking for the timeout time entered!" + "\n")
            break
        finally:
            textbox.insert(END,
                           "-------------------------------------------------------------------------------------------------\n\n")


def ShowInfoTextBox():
    """Inserts to the big textbox on the screen all the info about port scanning and examples/"""
    the_file = open('./TxtProj/AboutPortScanning.txt')
    textbox.insert(END, the_file.read())
    the_file.close()
    textbox.insert(END, f'For more information, please visit: ')
    textbox.insert(END, f'https://nmap.org/', hyperlink.add(partial(OpenLink, f'https://nmap.org/')))
    textbox.insert(END,
                   "\n\n----------------------------------------------------------------------------------------\n\n")


def CreateMadeScans():
    """Creating the made scans using a list"""

    r = 0  # The row which the widgets gets placed in
    for i in range(0, len(ready_scans),
                   2):  # Scanning through touples that contain ('NAME OF SCAN', 'SCAN OPTION', INFO ABOUT THE SCAN')
        t1 = ready_scans[i]  # Tuple1
        t2 = ready_scans[i + 1]  # Tuple2 - in the next place
        x = Button(ready_scan, text=t1[0], bd=2, command=partial(Scan, t1[1]), font=('TkDefaultFont', 9, 'bold')).grid(
            row=r, column=0, sticky='ew', pady=1, padx=(1, 1))  # Scan button
        y = Button(ready_scan, text='INFO', bd=2, command=partial(ShowINFO, f'INFO - {t1[0]}', t1[2]), fg=INFO_COLOR,
                   activeforeground=INFO_COLOR, font=('TkDefaultFont', 9, 'bold')).grid(row=r, column=1, pady=1,
                                                                                        padx=(0, 134),
                                                                                        sticky='ew')  # Info button
        x = Button(ready_scan, text=t2[0], bd=2, command=partial(Scan, t2[1]), font=('TkDefaultFont', 9, 'bold')).grid(
            row=r, column=2, sticky='ew', pady=1, padx=0)  # Scan button
        y = Button(ready_scan, text='INFO', bd=2, command=partial(ShowINFO, f'INFO - {t2[0]}', t2[2]), fg=INFO_COLOR,
                   activeforeground=INFO_COLOR, font=('TkDefaultFont', 9, 'bold')).grid(row=r, column=3, pady=1, padx=1,
                                                                                        sticky='ew')  # Info button
        r += 1  # Go down a row


def CreateCustomScan():
    """This function creates the GUI (buttons, labels, entries) for the custom scan."""

    r = 0  # Saves the row number
    xfont = "TkDefaultFont"  # Variable to save the font in case we want to change it
    xsize = 10  # Variable to save the size of the font in case we want to change it
    l = Label(vframe,
              text="Welcome to the Scan Generator! here you can make your own scan.\n*Default values are set, so you don't need to set everything*",
              font=("Arial", 12, 'bold', 'underline'), padx=2).grid(pady=(2, 18), row=r, column=0, sticky='nsew')
    r += 1

    # GUI for choosing the ports
    p_label = Label(vframe,
                    text="Specify Ports - By Default Uses 1000 Most Common Protocol ports\n*Check the INFO button for the available syntaxes*",
                    font=(xfont, xsize, 'bold'), padx=2, pady=2).grid(pady=(5, 2), row=r, column=0, sticky='nsew')
    p_info = Button(vframe, text="INFO", command=partial(ShowCustomINFO, "PORTS", "PORT_SPECIFICATION", "small"),
                    padx=2, pady=2, font=(xfont, xsize, 'bold'), bd=2, fg=INFO_COLOR, activeforeground=INFO_COLOR).grid(
        pady=(5, 2), row=r, column=1, sticky='nswe')
    r += 1
    port_entry = Entry(vframe, bd=5)
    port_entry.grid(columnspan=2, row=r, column=0, sticky='nsew')
    r += 1

    # GUI for choosing the time template (how aggressive/fast the scan will be)
    time_label = Label(vframe,
                       text='Set a timing template (Select Number) - By Default Uses Number 3\n0=paranoid | 1=sneaky | 2=polite | 3=normal | 4=aggressive | 5=insane',
                       font=(xfont, xsize, 'bold'), padx=2, pady=2).grid(pady=(20, 2), row=r, column=0, sticky='nsew')
    time_info = Button(vframe, text="INFO", command=partial(ShowCustomINFO, "TIME", "TIME_TEMPLATE", "small"), padx=2,
                       pady=2, font=(xfont, xsize, 'bold'), bd=2, fg=INFO_COLOR, activeforeground=INFO_COLOR).grid(
        pady=(20, 2), row=r, column=1, sticky='nswe')
    r += 1
    time_values = {"0 (Slow)": "-T0", "1 (Slow)": "-T1", "2 (Slow)": "-T2", "3 (Normal)": "-T3", "4 (Fast)": "-T4",
                   "5 (Fast)": "-T5", "Default": "default"}
    save_time = StringVar(value=" ")
    for text, value in time_values.items():
        rb = Radiobutton(vframe, text=text, variable=save_time, value=value)
        rb.grid(row=r, column=0)
        r += 1

    # GUI for choosing the TCP technique that will be used
    tcp_label = Label(vframe,
                      text="Select TCP Scan Technique\n*If a scan technique is not chosen, a SYN Scan will be performed*",
                      font=(xfont, xsize, 'bold'), padx=2, pady=2).grid(pady=(20, 2), row=r, column=0, sticky='nsew')
    tcp_info = Button(vframe, text="INFO", command=partial(ShowCustomINFO, "TCP TECHNIQUE", "TCP_TECHNIQUE", "big"),
                      padx=2, pady=2, font=(xfont, xsize, 'bold'), bd=2, fg=INFO_COLOR,
                      activeforeground=INFO_COLOR).grid(pady=(20, 0), row=r, column=1, sticky='nswe')
    r += 1
    tcp_values = {"SYN Scan (Popular)": "-sS", "TCP Scan": "-sT", "Null Scan": "-sN", "FIN Scan": "-sF",
                  "Xmas Scan": "-sX", "Window Scan": "-sW", "Maimon Scan": "-sM", "Idle Scan": "-sI:",
                  "FTP Bounce Scan": "-b", "Default": "default"}
    save_tcp_teq = StringVar(value=" ")
    for text, value in tcp_values.items():
        rb = Radiobutton(vframe, text=text, variable=save_tcp_teq, value=value)
        rb.grid(row=r, column=0)
        r += 1

    # GUI for choosing which TCP flags to turn ON
    flags_label = Label(vframe,
                        text="Select TCP Flags To Turn On - By Default None Are Set\n*This is an addition to the scan techniques*",
                        font=(xfont, xsize, 'bold'), padx=2, pady=2).grid(pady=(20, 2), row=r, column=0, sticky='nsew')
    flags_info = Button(vframe, text="INFO", command=partial(ShowCustomINFO, "TCP FLAGS", "TCP_FLAGS", "small"), padx=2,
                        pady=2, font=(xfont, xsize, 'bold'), bd=2, fg=INFO_COLOR, activeforeground=INFO_COLOR).grid(
        pady=(20, 0), row=r, column=1, sticky='nswe')
    r += 1
    flags_values = ["URG", "ACK", "PSH", "RST", "SYN", "FIN"]
    save_flags = []
    for value in flags_values:
        t = StringVar()
        cb = Checkbutton(vframe, text=value, variable=t, onvalue=value, offvalue="")
        cb.grid(row=r, column=0)
        save_flags.append((cb, t))
        r += 1

    # GUI for choosing a UDP/SCTP scan technique/s
    flags_label = Label(vframe,
                        text="Select UDP/SCTP Scan Techniques (Multiple scan techniques can be used)\n*By default none are used*",
                        font=(xfont, xsize, 'bold'), padx=2, pady=2).grid(pady=(20, 2), row=r, column=0, sticky='nsew')
    flags_info = Button(vframe, text="INFO",
                        command=partial(ShowCustomINFO, "UDP/SCTP TECHNIQUE", "UDP_SCTP_TECHNIQUE", "big"), padx=2,
                        pady=2, font=(xfont, xsize, 'bold'), bd=2, fg=INFO_COLOR, activeforeground=INFO_COLOR).grid(
        pady=(20, 0), row=r, column=1, sticky='nswe')
    r += 1
    USC_values = {"UDP Scan": "-sU", "SCTP INIT Scan": "-sY",
                  "SCTP COOKIE-ECHO Scan": "-sZ"}  # USC - shortcut for UDP, SCTP, COOKIE
    save_USC = []
    for text, value in USC_values.items():
        t = StringVar()
        cb = Checkbutton(vframe, text=text, variable=t, onvalue=value, offvalue="")
        cb.grid(row=r, column=0)
        save_USC.append((cb, t))
        r += 1

    # GUI for choosing which ASCII string will be sent in the packet
    payload_label = Label(vframe, text="Payload Option - Enter String\n(Append custom ASCII string to sent packets)",
                          font=(xfont, xsize, 'bold'), padx=2, pady=2).grid(pady=(20, 2), row=r, column=0,
                                                                            sticky='nsew')
    payload_info = Button(vframe, text="INFO", command=partial(ShowCustomINFO, "PAYLOAD", "PAYLOAD_OPTION", "small"),
                          padx=2, pady=2, font=(xfont, xsize, 'bold'), bd=2, fg=INFO_COLOR,
                          activeforeground=INFO_COLOR).grid(pady=(20, 2), row=r, column=1, sticky='nswe')
    r += 1
    payload_entry = Entry(vframe, bd=5)
    payload_entry.grid(columnspan=2, row=r, column=0, sticky='nsew')
    r += 1

    # GUI for choosing advanced options
    options_label = Label(vframe, text="Select Advanced Options\n*By default none are activated*",
                          font=(xfont, xsize, 'bold'), padx=2, pady=2).grid(pady=(20, 2), row=r, column=0,
                                                                            sticky='nsew')
    options_info = Button(vframe, text="INFO", command=partial(ShowCustomINFO, "ADVANCED", "ADVANCED_OPTIONS", "big"),
                          padx=2, pady=2, font=(xfont, xsize, 'bold'), bd=2, fg=INFO_COLOR,
                          activeforeground=INFO_COLOR).grid(pady=(20, 0), row=r, column=1, sticky='nswe')
    r += 1
    options_dict = {"Enable Vulnerability Check (Recommended)": "--script vuln",
                    "Enable Service/Version Detection (Popular)": "-sV", "Enable OS Detection (Popular)": "-O",
                    "Enable Script Scan": "-sC", "Enable Packet-Trace": "--packet-trace", "Use Fragment Packets": "-f",
                    "Use Badsum": "--badsum", "Increase Verbosity Level": "-v", "Increase Debugging Level": "-d"}
    save_options = []
    for text, value in options_dict.items():
        t = StringVar()
        cb = Checkbutton(vframe, text=text, variable=t, onvalue=value, offvalue="")
        cb.grid(row=r, column=0)
        save_options.append((cb, t))
        r += 1

    # GUI for submitting the scan (sending it to the function which parses the scan parameters and creates a proper option for the usage of nmap in terminal form)
    submit_button = Button(vframe,
                           command=partial(CreateOption, port_entry, save_time, save_tcp_teq, save_flags, save_USC,
                                           payload_entry, save_options), bd=2, text="ACTIVATE SCAN", padx=2,
                           font=("Arial", 12, 'bold'), fg="blue", activeforeground="green")
    submit_button.grid(columnspan=2, pady=(20, 2), row=r, column=0, sticky='nsew')


def SaveSettings():
    """This functions saves the settings (which are on the Options/Settings frame)"""

    # Checking the GUI for the information about the settings
    _log = "OFF"
    _timeout = ReturnDATA("TIME_OUT", "./TxtProj/CONFIG.txt")
    _vuln = "OFF"
    _conn = "OFF"
    if (Log_Var.get() == 1):
        _log = "ON"
    x = timeout_e.get()
    if (x.isdigit()):
        _timeout = x
    elif (x == "" or x.isspace()):
        _timeout = "None"
    if (Vuln_Var.get() == 1):
        _vuln = "ON"
    if (Conn_Var.get() == 1):
        _conn = "ON"

    file = open('./TxtProj/CONFIG.txt', 'r')  # Reading the file
    lines = file.readlines()

    skip_line = False
    settings = {": SAVE_LOG": _log, ": TIME_OUT": _timeout, ": VULN_CHECK": _vuln,
                ": SAVE_CONN": _conn}  # dictionary of "identifier of value": "new value"
    new_lines = []  # dictionary to contain the new settings

    for line in lines:
        if (skip_line == True):  # Means we changed an old value with new value in the previous iteration
            skip_line = False
            continue
        line = line.rstrip("\n")
        line_cmp = line.split("#")[0]
        if (len(line_cmp) > 0 and line_cmp[-1] == " "):
            line_cmp = line_cmp[:-1]
        if (line_cmp not in settings):  # Not a line which is an identifier of a value
            new_lines.append(line)
        else:
            value = settings[line_cmp]  # new value
            new_lines.append(line)  # append this line (identifier) back
            new_lines.append(value)  # append new value (will be in the next line)
            skip_line = True  # skip next line

    f = open('./TxtProj/CONFIG.txt', 'w')  # Writing to the file the new settings
    for line in new_lines:
        f.write(f'{line}\n')
    f.close()


def CreateSettings():
    """This functions creates the general options/settings for the port scanner"""

    global Log_Var  # Creating a global var and a checkbutton for the setting of saving the result of the scan to the log
    Log_Var = IntVar()
    cb_log = Checkbutton(options_frame, text="Save scan result in the log file of the device scanned", onvalue=1,
                         offvalue=0, variable=Log_Var, font=('Arial', 11, 'bold'))
    cb_log.pack(padx=2, pady=2, side=TOP, anchor=NW)
    if (ReturnDATA("SAVE_LOG", "./TxtProj/CONFIG.txt").lower() == "on"):
        Log_Var.set(1)

    timeout_l = Label(options_frame, text="Timeout (in seconds) for a scan on each device (leave empty for no timeout)",
                      font=('Arial', 11, 'bold')).pack(padx=10, pady=(2, 0), side=TOP, anchor=NW)
    global timeout_e  # Creating a global var and an entry for the setting that saves the timeout (or no timeout) for the scan on each device
    timeout_e = Entry(options_frame, bd=5)
    timeout_e.pack(side=TOP, fill='x', padx=(10, 2))
    x = ReturnDATA("TIME_OUT", "./TxtProj/CONFIG.txt")
    if (x.isdigit()):
        timeout_e.insert(0, x)

    global Vuln_Var  # Creating a global var and a checkbutton for the setting of providing general links for a reliable website of CVE (Common Vulnerabilities and Exposures)
    Vuln_Var = IntVar()
    cb_vuln = Checkbutton(options_frame,
                          text="Provide link to vulnerabilities in CVE data base after scan results (longer waiting time)",
                          onvalue=1, offvalue=0, variable=Vuln_Var, font=('Arial', 11, 'bold'))
    cb_vuln.pack(padx=2, pady=(4, 0), side=TOP, anchor=NW)
    if (ReturnDATA("VULN_CHECK", "./TxtProj/CONFIG.txt").lower() == "on"):
        Vuln_Var.set(1)

    global Conn_Var  # Creating a global var for saving the connectivity in the log file
    Conn_Var = IntVar()
    cb_conn = Checkbutton(options_frame, text="Enable saving the connectivity changes of the device in his log file",
                          onvalue=1, offvalue=0, variable=Conn_Var, font=('Arial', 11, 'bold'))
    cb_conn.pack(padx=2, pady=2, side=TOP, anchor=NW)
    if (ReturnDATA("SAVE_CONN", "./TxtProj/CONFIG.txt").lower() == "on"):
        Conn_Var.set(1)

    s_button = Button(options_frame, bd=2, command=SaveSettings, text="Save These Settings (On Program's Startup)",
                      font=("Arial", 12, 'bold'), fg="blue",
                      activeforeground="green")  # Button that calls for the function whom saves these settings
    s_button.pack(side=TOP, fill='x', pady=2, padx=2)


def ClearTextBox():
    """Clears the big textbox on the main screen"""

    textbox.config(state=NORMAL)
    textbox.delete('1.0', END)


# ~~~~~~~~~~~~~~~~~~~#

# ~~~~~before running~~~~~#
subprocess.check_output('./Terminal.sh Privilege', shell=True).decode(
    'utf-8')  # Get's root privilege for this current terminal session
subprocess.check_output('mkdir -p LogProj',
                        shell=True)  # Makes a folder to store the log files (if it's not created yet)
if (not (os.path.isfile('LogProj/shared_log'))):
    subprocess.check_output('touch LogProj/shared_log', shell=True)
# ~~~~~~~~~~~~~~~~~~~~~~~~#

# ~~~~~configuration~~~~~#
# VARIABLES
cb_list = []  # List that contains the checkbutton of the devices (the checkbuttons with ip/mac/name/connection)
mac_list = []  # List of all the MAC addresses of the devices that are/were online
ip_list = []  # List of all the IP addresses of the devices that are/were online
localhost = '127.0.0.1'  # Local host variable

ready_scans = [("TCP CONNECT Scan", "-sT", "TCP_CONNECT_SCAN"),
               # This is the information needed for the function that builds the ready scans (CreadeMadeScans function)
               ("TCP SYN Scan (Popular)", "-sS", "TCP_SYN_SCAN"),
               ("UDP Scan", "-sU", "UDP_SCAN"),
               ("SCTP INIT Scan", "-sY", "SCTP_INIT_SCAN"),
               ("TCP NULL Scan", "-sN", "TCP_NULL_SCAN"),
               ("IP PROTOCOL Scan", "-sO", "IP_PROTOCOL_SCAN"),
               ("TCP ACK Scan", "-sA", "TCP_ACK_SCAN"),
               ("Aggressive Scan (Popular)", "-T4 -A", "AGGRESSIVE_SCAN")]
GREEN = "#006110"
RED = "#860000"
INFO_COLOR = "#3E004F"
ORANGE = "#BA4A00"
BG_COLOR = "#D2FFE9"
column_scroll = 0  # Column counter for the checkbuttons grid
lock = threading.Lock()  # Thread lock
phones_list = ["iphone", "ipad", "ipod", "galaxy", "android", "nokia", "samsung", "huawei", "oneplus", "xiaomi", "zte",
               "oppo", "vivo", "motorola"]  # List of known phone names

my_ip = subprocess.check_output('./Terminal.sh GetMyIP', shell=True).decode(
    'utf-8')  # Gets this computer's IP (from the messaging)
my_mac = subprocess.check_output('./Terminal.sh GetMyMAC', shell=True).decode(
    'utf-8')  # Getting this computers MAC address
router_mac = subprocess.check_output('./Terminal.sh GetRouterMAC', shell=True).decode(
    'utf-8')  # Getting the router's MAC address

# ~~~~~~~~~~#

# TKINTER
root = Tk()

try:
    SCREEN_SIZE = ReturnDATA("SCREEN_SIZE",
                             "./TxtProj/CONFIG.txt").lower()  # Gets the screen size from configuration file
    if (SCREEN_SIZE == "fullscreen"):
        root.attributes('-zoomed', True)  # Make the GUI fullscreen
    else:
        root.geometry(SCREEN_SIZE)
except:
    root.attributes('-zoomed', True)  # Make the GUI fullscreen

root.title("Port Scanner GUI")  # Changing the title of the window
root.pack_propagate(0)
width = root.winfo_screenwidth()  # Getting width of the screen
height = root.winfo_screenheight()  # Getting the height of the screen

# MANAGING THE VARIABLES AND FRAME FOR THE DEVICES ICONS ON SCREEN
img = Image.open('./PicProj/computer_icon.png')  # Opening the image of computer icon
pc_img = ImageTk.PhotoImage(img)  # Saving the image
img = Image.open('./PicProj/cellphone_icon.png')  # Opening the image of cellphone icon
phone_img = ImageTk.PhotoImage(img)  # Saving the image
img = Image.open('./PicProj/router_icon.png')  # Opening the image of the router
router_img = ImageTk.PhotoImage(img)  # Saving the image
img = Image.open('./PicProj/log_icon.png')
log_img = ImageTk.PhotoImage(img)

frame = ScrollableFrameH(root, 165, root.winfo_screenwidth())  # Frame for scrollbar (on top of the screen)
frame.pack(side=TOP)  # Putting the frame (on top)

wait_label = Label(frame.scrollable_frame,
                   text="Please Wait A Few Seconds ...")  # Label to tell the user to wait untill the devices show up on screen
wait_label.config(font=("TkDefaultFont", 15, 'bold'))  # Config the Label
wait_label.pack(side=TOP)  # Place the label on op
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

left_frame = Frame(root, height=height, width=width)  # The scrollbar frame takes 140 pixels

# MAKING THE FRAME WITH THE ALREADY MADE SCANS
ready_scan = LabelFrame(left_frame, text="Ready To Use/Already Made Scans (Select The Devices To Scan First)")
ready_scan.pack(side=TOP, padx=5, pady=5, anchor=NW)  # Frame for the ready to use scans
CreateMadeScans()
ready_scan.update()
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# MAKING THE FRAME WITH OPTIONS AND SETTINGS
options_frame = LabelFrame(left_frame, text="Options/Settings", height=195, width=ready_scan.winfo_reqwidth())
options_frame.pack(side=TOP, padx=5, pady=0, anchor=NW)
options_frame.pack_propagate(0)  # Prevent frame from shrinking
options_frame.grid_propagate(0)
CreateSettings()
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

port_manage = PortControl(root)
close_ports_button = Button(left_frame, bd=2, text="Manage/Close Ports On Your PC (New Window With Port Options)",
                            command=port_manage.ClosePorts, bg='black', fg='red', activebackground='black',
                            activeforeground='green',
                            font=('Ariel', 9, 'bold')
                            )  # Makes a button that creates popup window with options to close ports
close_ports_button.pack(side=TOP, padx=5, pady=(10, 0), anchor=NW, fill='x')

# MAKING THE FRAME WITH THE OPTIONS FOR THE CUSTOMIZABLE SCAN
custom_scan = LabelFrame(left_frame, text="Custom Scan/Scan Generator (Select The Devices To Scan First)",
                         height=height, width=ready_scan.winfo_reqwidth())
custom_scan.pack(side=TOP, padx=5, pady=5, anchor=NW)  # Frame for the customizable scans
custom_scan.pack_propagate(0)  # Prevent frame from shrinking
custom_scan.grid_propagate(0)
vframe = VerticalScrolledFrame(custom_scan)  # Frame with vertical scrollbar for the custom_scan frame
vframe.pack(fill='both', expand=True)  # Make the scrollable frame the whole size of the frame
CreateCustomScan()
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

left_frame.pack(side=LEFT, padx=5, pady=5, anchor=N)

# MAKING THE BUTTONS AND FRAME THAT HAVE TO DO WITH THE RESULTS TEXTBOX
ft = LabelFrame(root, text="Scan Output - Results", height=height,
                width=width)  # A frame to contain the other 2 frames (because .pack causes problems)
ft.pack(side=TOP, padx=5, pady=10, anchor=N)
frame_textbox = Frame(ft)  # Frame above the textbox to contain the two buttons bellow
frame_textbox.pack(side=TOP, padx=5, anchor=NW, fill='x')
show_info_button = Button(frame_textbox, text="INFO + EXAMPLES", command=ShowInfoTextBox, bd=2,
                          font=('Ariel', 9, 'bold'))  # Shows info about the port scanning and what the results mean.
show_info_button.pack(side=LEFT)
clear_button = Button(frame_textbox, text="CLEAR", command=ClearTextBox, bd=2,
                      font=('Ariel', 9, 'bold'))  # Button to clear what's in the textbox
clear_button.pack(side=LEFT, fill='x', expand=True)  # Button to clear the text in the text box on screen

result_frame = Frame(ft, height=height, width=width)
result_frame.pack(side=TOP, padx=5, pady=5, anchor=N)  # Frame for the custom scans
result_frame.pack_propagate(0)
result_frame.grid_propagate(0)

# Textbox var (in result_frame) - the results of the scan go in there
ttextbox = ScrollableTextBox(result_frame)
textbox = ttextbox.textbox
# Adding hyperlink options
hyperlink = HyperlinkManager(textbox)
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

# ~~~~~#

if __name__ == "__main__":
    try:
        SLEEP_THREAD = int(ReturnDATA("SLEEP_THREAD", "./TxtProj/CONFIG.txt"))
    except:
        SLEEP_THREAD = 5
    devices_thread = threading.Thread(target=DevicesOnScreen, daemon=True)
    devices_thread.start()

    global peer
    peer = Peer(my_ip, 5050)
    peer.setDaemon(True)
    peer.start()

    root.mainloop()

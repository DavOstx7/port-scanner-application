#!usr/bin/env python

from guicontrol import ScrollableTextBox, ScrollableFrameH
from tkinter import *
import subprocess
from functools import partial


class PortControl():
    """This class contains the GUI and functions/methods for closing open ports or blocking/opening traffic through ports in the ubuntu firewall"""

    def __init__(self, root):
        self.root = root
        self.port_window = None
        self.port_cb = None
        self.close_frame = None
        self.block_frame = None
        self.close_txt = None
        self.block_txt = None
        self.block_entry = None

    def KillProcess(self):
        """Killing the process of a specific open port selected in the GUI"""

        for cb_tuple in self.port_cb:
            cb = cb_tuple[0]  # Checkbutton
            var = cb_tuple[1]  # State - selected or not selected
            if (var.get() != '-1'):  # If the checkbutton is selected
                try:
                    if (var.get() == '5050'):  # responsible for socket
                        MsgBox = messagebox.askquestion('Close Port',
                                                        'Are you sure you want to close this port? it is responsible for the socket p2p commiunication of this program',
                                                        icon='warning')  # Making a waring question
                        if MsgBox == 'no':
                            continue  # skip over this port

                    _ = subprocess.check_output(f'./Terminal.sh KillProcess {var.get()}', shell=True).decode(
                        'utf-8')  # Terminate process
                    self.port_cb.remove(cb_tuple)
                    cb.destroy()  # Removing the checkbutton from the GUI
                    self.close_txt.insert(END, f'Port {var.get()} was succesfully closed')  # Success message
                except:
                    self.close_txt.insert(END, 'An error has occurred\nTry checking for typos\n')  # Error message

    def Status_UFW(self):
        """Showing the status of the current firewall"""

        try:
            output = subprocess.check_output('./Terminal.sh UFW status numbered', shell=True).decode('utf-8')
            self.block_txt.delete('1.0', END)
            if (output == 'Status: active\n'):  # Telling the user if he doesn't have any rules
                output += f'You dont have any rules in your firewall currently!'
            self.block_txt.insert(END, output)
        except:
            self.block_txt.insert(END, 'An error has occurred\nTry checking for typos\n')

    def Enable_UFW(self):
        """Enabling the firewall of ubuntu (turning it on)"""

        try:
            output = subprocess.check_output('./Terminal.sh UFW enable', shell=True).decode('utf-8')
            self.block_txt.delete('1.0', END)
            self.block_txt.insert(END, output)
        except:
            self.block_txt.insert(END, 'An error has occurred\nTry checking for typos\n')

    def Disable_UFW(self):
        """Disabling the firewall of ubuntu (turning it off)"""

        try:
            output = subprocess.check_output('./Terminal.sh UFW disable', shell=True).decode('utf-8')
            self.block_txt.delete('1.0', END)
            self.block_txt.insert(END, output)
        except:
            self.block_txt.insert(END, 'An error has occurred\nTry checking for typos\n')

    def BLOCK_UFW(self):
        """Blocking a specific port in the ubuntu firewall (blocking traffic)"""

        try:
            output = subprocess.check_output(f'./Terminal.sh UFW deny {self.block_entry.get()}', shell=True).decode(
                'utf-8')
            self.block_txt.delete('1.0', END)
            self.block_txt.insert(END, output)
            self.Status_UFW()  # Showing the new status
        except:
            self.block_txt.insert(END, 'An error has occurred\nTry checking for typos\n')

    def OPEN_UFW(self):
        """Opening a specific port in the ubuntu firewall (allowing traffic)"""

        try:
            output = subprocess.check_output(f'./Terminal.sh UFW allow {self.block_entry.get()}', shell=True).decode(
                'utf-8')
            self.block_txt.delete('1.0', END)
            self.block_txt.insert(END, output)
            self.Status_UFW()  # Showing the new status
        except:
            self.block_txt.insert(END, 'An error has occurred\nTry checking for typos\n')

    def DELETE_UFW(self):
        """Deleteing a rule --> removing the blocking/opening of a specific port"""

        try:
            _ = subprocess.check_output(f'echo y | ./Terminal.sh UFW delete {self.block_entry.get()}',
                                        shell=True).decode('utf-8')
            self.block_txt.delete('1.0', END)
            self.block_txt.insert(END, f'Rule {self.block_entry.get()} was successfully deleted')
            self.Status_UFW()  # Showing the new status
        except:
            self.block_txt.insert(END, 'An error has occurred\nTry checking for typos\n')

    def destroy_pop(self):
        self.port_window.destroy()

    def ClosePorts(self):
        """Manages the whole closing ports part of the program"""

        self.port_window = Toplevel(self.root)  # Creating a new window
        self.port_window.geometry('1000x620')  # Setting the size
        self.port_window.resizable(False, False)
        self.port_window.title("Port Control")  # Title for the new window

        destory_button = Button(self.port_window, text='CLOSE', command=self.destroy_pop, bd=2, padx=10, pady=10,
                                font=('bold')).pack(side=BOTTOM)  # Create a close button for the popup

        # Creating frame for closing the port
        self.close_frame = LabelFrame(self.port_window,
                                      text="Close Ports (Kill Process) - port 5050 is used in this program",
                                      height=self.root.winfo_screenheight(),
                                      width=497)  # Frame for closing/killing ports
        self.close_frame.pack(side=LEFT, padx=(2, 1))
        self.close_frame.pack_propagate(0)
        label_port = Label(self.close_frame, text="Select The Open Ports You Want To Close/Kill", pady=10).pack(
            side=TOP)  # Label to tell the user to select the ports
        frameH = ScrollableFrameH(self.close_frame, 35,
                                  self.root.winfo_screenwidth())  # Making a scrollable horizontal frame
        frameH.pack(side=TOP)  # Packing the frame
        ports_list = subprocess.check_output('./Terminal.sh OpenPorts', shell=True).decode(
            'utf-8')  # Getting all the open ports at the moment
        ports_list = ports_list.splitlines()
        # Splitting the ports to a list
        self.port_cb = []  # List of ports checkbuttons
        for port in ports_list:
            t = StringVar()
            cb = Checkbutton(frameH.scrollable_frame, text=port, variable=t, compound='bottom', offvalue='-1',
                             onvalue=port.split()[1])  # Create checkbutton for ports
            cb.deselect()  # Auto diselect (tkinter bug)
            cb.pack(side=LEFT, padx=10)
            self.port_cb.append((cb, t))  # Add the cb to the list

        # Creating frame for blocking/allowing traffic from specific ports in the firewall
        self.block_frame = LabelFrame(self.port_window, text="Block Ports (Ubuntu FireWall - UFW)",
                                      height=self.root.winfo_screenheight(),
                                      width=547)  # Frame for the blocking ports ufw
        self.block_frame.pack(side=LEFT, padx=(1, 2))
        self.block_frame.pack_propagate(0)

        close_port = Button(self.close_frame, text="CLOSE/KILL", command=self.KillProcess, bd=2,
                            font=('bold'))  # Button to kill the process
        close_port.pack(side=TOP, fill='x', padx=1, pady=1)

        status_button = Button(self.block_frame, text="VIEW STATUS - Ubuntu's Firewall", command=self.Status_UFW,
                               bd=2)  # Button to show status of the firewall
        status_button.pack(side=TOP, fill='x', padx=1, pady=1)
        enable_button = Button(self.block_frame, text="ENABLE UFW", command=self.Enable_UFW,
                               bd=2)  # Button to enable the firewall
        enable_button.pack(side=TOP, fill='x', padx=1, pady=1)
        disable_button = Button(self.block_frame, text="DISABLE UFW", command=self.Disable_UFW,
                                bd=2)  # Button to disable the firewall
        disable_button.pack(side=TOP, fill='x', padx=1, pady=1)
        bp_label = Label(self.block_frame,
                         text="~Enter a port or a protocol to block/open (rule) a port \n~Enter row number of a rule to delete him\n(row number is written next to the rule)",
                         font=('bold'), pady=2).pack(side=TOP, pady=(19, 1), fill='x')
        self.block_entry = Entry(self.block_frame,
                                 bd=5)  # Making entry for entering for port/protocol to block/open ports, or entering number of a rule to delete him,
        self.block_entry.pack(expand=True, fill='x')

        b1 = Button(self.block_frame, text="BLOCK PORT", bd=2, font=('bold'),
                    command=self.BLOCK_UFW)  # Button to block the port (deny traffic)
        b1.pack(side=TOP, padx=1, pady=1, fill='x')

        b2 = Button(self.block_frame, text="OPEN PORT", bd=2, font=('bold'),
                    command=self.OPEN_UFW)  # Button to open a port (allow traffic)
        b2.pack(side=TOP, padx=1, pady=1, fill='x')

        b3 = Button(self.block_frame, text="DELETE RULE", bd=2, font=('bold'),
                    command=self.DELETE_UFW)  # Button to delete a rule(rule = allow/deny traffic)
        b3.pack(side=TOP, padx=1, pady=1, fill='x')

        # Making a textbox to put the results of the closing port process
        tclose_txt = ScrollableTextBox(self.close_frame)
        self.close_txt = tclose_txt.textbox

        # Making a textbox to put the results of changing firewall rules (you can block ports with this)
        tblock_txt = ScrollableTextBox(self.block_frame)
        self.block_txt = tblock_txt.textbox

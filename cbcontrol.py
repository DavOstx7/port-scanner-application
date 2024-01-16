#!/usr/bin/env python3
import threading
from tkinter import *
import os
from datetime import datetime
import subprocess
from guicontrol import ScrollableTextBox
from peer2peer import Peer
import time


class MyCheckButton(Checkbutton):
    """Custom class of a CheckButton with extra variables"""

    def __init__(self, container, peer, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.log_button = None  # Log button to show the history of the device
        self.status = StringVar()  # Stores the status of the checkbox: "0" = not selected, "1" = selected
        self.ip = ""  # IP of the device
        self.name = ""  # Name of the device
        self.connection = ""  # Connection: CONNECTED or DISCONNECTED
        self.mac = ""  # MAC address of the device
        self.top = None  # Popup window for the log data
        self.textbox = None  # Textbox var
        self.localhost = '127.0.0.1'
        self.root = None
        self.peer = peer

    def set_values(self, root, my_mac, ip=" ", name="", connection="", mac=""):
        self.root = root
        self.ip = ip  # IP of the device
        self.name = name  # Name of the device
        self.connection = connection  # Is the device connected or disconnected
        self.mac = mac
        self.log_path = f'./LogProj/{self.mac}'
        if (mac == my_mac):
            self.log_path = f'./LogProj/My_Computer'
            self.mac = subprocess.check_output('./Terminal.sh GetMyMAC', shell=True).decode('utf-8')
        if (ip == self.localhost):
            self.log_path = f'./LogProj/localhost'

    def get_values(self):
        return (self.ip, self.name, self.connection, self.mac)

    def CreateTextBox(self):
        """Makes a TextBox for the popup with a scrollbar"""

        x = ScrollableTextBox(self.top)
        self.textbox = x.textbox

    # Set functions
    def set_ip(self, ip):
        self.ip = ip

    def set_name(self, name):
        self.name = name

    def set_connection(self, connection):
        self.connection = connection

    def set_status(self, status):
        self.status = status

    def set_mac(self, mac):
        self.mac = mac

    # Get functions
    def get_ip(self):
        return self.ip

    def get_name(self):
        return self.name

    def get_connection(self):
        return self.connection

    def get_status(self):
        return self.status

    def get_mac(self):
        return self.mac

    def update_text(self):
        """Updates the text of the information (ip, mac, connection, name)"""

        self.config(text=f'{self.ip}\n{self.name}\n{self.mac}\n{self.connection}')

    def destroy_pop(self):
        self.top.destroy()

    def DeleteAllLogFiles(self):
        """Deletes all of the log files after permission"""

        MsgBox = messagebox.askquestion('DELETE LOG FILES',
                                        'Are you sure you want to delete the log files of all the devices?',
                                        icon='warning')  # Making a waring question
        if MsgBox == 'yes':
            subprocess.check_output('rm ./LogProj/*', shell=True)  # Deleting all of the log files (* = everything)
            messagebox.showinfo(title="",
                                message="All of the log files were deleted successfully!")  # Telling the user that the files were delete

    def add_to_log(self, message):
        """Adds a log message to the log file"""

        if (os.path.exists(self.log_path) == False):  # If a log file doesn't exist or it got deleted, create one
            subprocess.check_output(f'touch {self.log_path}', shell=True)
        f = open(f'{self.log_path}', "a")  # Opening the file
        f.write(f'[+] {datetime.now().isoformat(" ", "seconds")} {message}\n')  # Writing to the file
        f.close()  # Closing the file

    def save_log(self):
        """Saves the text thats currently in the textbox"""

        if (os.path.exists(self.log_path) == False):  # If a log file doesn't exist or it got deleted, create one
            subprocess.check_output(f'touch {self.log_path}', shell=True)
        current_data = self.textbox.get("1.0", "end-1c")  # Getting whats currently in the textbox
        subprocess.check_output(f'echo "{current_data}" > {self.log_path}',
                                shell=True)  # Saving whats currently in the textbox in the log file

    def clear_log(self):
        """Cleares the contents of the textbox and logfile"""

        MsgBox = messagebox.askquestion('DELETE CONTENTS',
                                        'Are you sure you want to delete the contents of this log file?',
                                        icon='warning')  # Making a waring question
        if MsgBox == 'yes':
            subprocess.check_output(f'> {self.log_path}', shell=True)
            self.textbox.delete('1.0', END)

    def send_msg(self):
        """sending message to this device's IP (this device's IP is not ours IP)"""

        data = self.textbox.get("1.0", "end-1c")
        if (data != "" and data.isspace() == False):
            self.peer.set_reciever(self.ip, 5050)
            self.peer.send(data)

    def msg_window(self):
        """Creating the message window (GUI)"""

        self.destroy_pop()
        self.top = Toplevel(self.root)  # Creates Popup
        self.top.title(f'Message {self.name}')  # Sets title
        self.top.geometry('450x550')  # Sets size
        y = Button(self.top, text="Send The Message (which is in the textbox)", command=self.send_msg, bd=2, pady=10,
                   padx=10).pack(side=BOTTOM)
        self.CreateTextBox()

    def show_options(self):
        """Shows the log data on a popup window with a scrollbar"""

        self.top = Toplevel(self.root)  # Creates Popup
        self.top.title(f'History/Log and Message for {self.name}')  # Sets title
        self.top.geometry('550x550')  # Sets size
        destory_button = Button(self.top, text='CLOSE', command=self.destroy_pop, bd=2, padx=10, pady=10,
                                font=('bold')).pack(side=BOTTOM)  # Create a close button for the popup

        msg_button = Button(self.top, text='Send A Message To This Device', command=self.msg_window, bd=2, padx=10,
                            pady=10)
        msg_button.pack(side=BOTTOM, fill='x', expand=True)

        if (self.ip == self.peer.my_ip or self.ip == '127.0.0.1'):
            msg_button.config(text="Send A Message To Yourself")

        delete_button = Button(self.top, text='Delete All Of The Log Files', command=self.DeleteAllLogFiles, bd=2,
                               padx=10, pady=10).pack(side=BOTTOM, fill='x',
                                                      expand=True)  # Create a deleting button for all of the devices's log files
        clear_button = Button(self.top, text="Clear The Log Data Of This Device", command=self.clear_log, bd=2, padx=10,
                              pady=10).pack(side=BOTTOM, fill='x',
                                            expand=True)  # Create a clearing button for the contents of the log file
        save_button = Button(self.top, text='Save In The Log File What Is In The Textbox', command=self.save_log, bd=2,
                             padx=10, pady=10).pack(side=BOTTOM, fill='x', expand=True)  # Create a saving button
        self.CreateTextBox()  # Creates textbox to put the log data in

        if (os.path.exists(self.log_path) == False):  # If a log file doesn't exist or it got deleted, create one
            subprocess.check_output(f'touch {self.log_path}', shell=True)

        log_data = subprocess.check_output(f'cat {self.log_path}', shell=True).decode(
            'utf-8')  # Shows the data in the log file. It's like reading the file
        self.textbox.insert(END, f'{log_data}')  # Inserts the log data to the textbox

    def OptionsButton(self, container, r, c):
        """Creates an options button"""

        self.log_button = Button(container, text='Options (Log|Msg)', command=self.show_options, bd=2, bg='black',
                                 fg='red', activebackground='black', activeforeground='green',
                                 font=('Ariel', 9, 'bold'))
        self.log_button.grid(row=r, column=c, sticky='nsew')
        if (self.ip == self.peer.my_ip or self.ip == '127.0.0.1'):
            self.log_button.config(text="Options (Log)")


class SharedLog(threading.Thread):
    """This class is responsible for the messages recieved"""

    def __init__(self, container, pic, root, peer):
        threading.Thread.__init__(self, name="check_msgs")
        self.pic = pic
        self.container = container
        self.root = root
        self.textbox = None
        self.top = None
        self.pic_label = None
        self.peer = peer
        self.path = './LogProj/shared_log'

    def CreateTextBox(self, container):
        """Makes a TextBox for the popup with a scrollbar"""

        x = ScrollableTextBox(container)
        self.textbox = x.textbox

    def DeleteFile(self):
        """Deletes this shared log file"""

        MsgBox = messagebox.askquestion('DELETE File', 'Are you sure you want to delete this file?',
                                        icon='warning')  # Making a waring question
        if MsgBox == 'yes':
            subprocess.check_output(f'rm {self.path}', shell=True)  # Deleting all of the log files (* = everything)
            messagebox.showinfo(title="",
                                message="This file was deleted successfully!")  # Telling the user that the files were delete
            self.top.destroy()

    def save_file(self):
        """Saves the text thats currently in the textbox"""

        if (os.path.exists(self.path) == False):  # If a log file doesn't exist or it got deleted, create one
            subprocess.check_output(f'touch {self.path}', shell=True)
        current_data = self.textbox.get("1.0", "end-1c")  # Getting whats currently in the textbox
        subprocess.check_output(f'echo "{current_data}" > {self.path}',
                                shell=True)  # Saving whats currently in the textbox in the log file

    def show(self):
        """Builds the GUI which opens after button press"""

        self.top = Toplevel(self.root)  # Creates Popup
        self.top.title(f'View the messages from your local network peers!')  # Sets title
        self.top.geometry('750x750')  # Sets size

        destory_button = Button(self.top, text='CLOSE', command=self.top.destroy, bd=2, padx=10, pady=10,
                                font=('bold')).pack(side=BOTTOM)  # Create a close button for the popup

        delete_button = Button(self.top, text='Delete This File', command=self.DeleteFile, bd=2, padx=10, pady=10).pack(
            side=BOTTOM, fill='x')  # Create a deleting button for all of the devices's log files
        save_button = Button(self.top, text='Save In The File What Is In The Textbox', command=self.save_file, bd=2,
                             padx=10, pady=10).pack(side=BOTTOM, fill='x')  # Create a saving button
        self.CreateTextBox(self.top)  # Creates textbox to put the log data in

        if (os.path.exists(self.path) == False):  # If a log file doesn't exist or it got deleted, create one
            subprocess.check_output(f'touch {self.path}', shell=True)

        data = subprocess.check_output(f'cat {self.path}', shell=True).decode(
            'utf-8')  # Shows the data in the log file. It's like reading the file
        self.textbox.insert(END, f'{data}')  # Inserts the log data to the textbox

        self.pic_label.config(text="No New Messages")

    def write(self, msg):
        """Writing to the file"""

        if (os.path.exists(self.path) == False):  # If a log file doesn't exist or it got deleted, create one
            subprocess.check_output(f'touch {self.path}', shell=True)

        f = open(f'{self.path}', "a")  # Opening the file
        f.write(f'{msg}')  # Writing to the file
        f.close()  # Closing the file

    def build(self):
        """Building the GUI"""
        self.pic_label = Label(self.container, image=self.pic, compound="top", text="No New Messages")
        self.pic_label.grid(row=0, column=0)

        button = Button(self.container, bd=2, bg='black', text="Open Shared Log", command=self.show, fg='red',
                        activebackground='black', activeforeground='green', font=('Ariel', 9, 'bold'))
        button.grid(row=1, column=0, sticky='nsew')

    def recieve(self):
        """This functions checks for new messages every couple of seconds, and updates the text on the GUI if there is a new message and in the file"""

        while True:
            data = self.peer.get_data()
            if (data.isspace() == False and data != ""):
                self.write(data)  # Writing to the file
                self.pic_label.config(text="There Is A New Message!")  # Updating the label
            time.sleep(2)

    def run(self):
        """activating the thread"""

        self.recieve()

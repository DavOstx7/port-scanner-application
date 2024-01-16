import socket
import threading
import time
from tkinter import messagebox
from datetime import datetime


class Peer(threading.Thread):
    """This class is responsible for the connectivity between two computers using sockets"""

    def __init__(self, my_ip, my_port, other_ip=None, other_port=None):
        threading.Thread.__init__(self, name="messenger_receiver")
        self.my_ip = my_ip
        self.my_port = my_port
        self.other_ip = other_ip
        self.other_port = other_port
        self.gather_data = ""

    def set_reciever(self, other_ip, other_port):  # setting values
        self.other_ip = other_ip
        self.other_port = other_port

    def listen(self):
        """listening for connections and data"""

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('0.0.0.0', self.my_port))  # listening to every connection
        sock.listen(10)
        while True:
            try:
                connection, client_address = sock.accept()
            except:  # probably the user closed port 5050
                break
            try:
                full_message = ""
                while True:
                    data = connection.recv(1024)
                    full_message = full_message + data.decode('utf-8')
                    if not data:  # if there is no more data
                        self.gather_data += f'[+] {datetime.now().isoformat(" ", "seconds")} - {client_address} sent:\n{full_message.strip()}\n----------------------------------------------------\n'
                        break
            finally:
                try:
                    connection.shutdown(2)
                except:
                    pass
                finally:
                    connection.close()

    def send(self, message):
        """trying to connect to another computer and send him the message"""

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((self.other_ip, self.other_port))
            s.sendall(message.encode('utf-8'))
            messagebox.showinfo('Success!', f'The message was sent to {self.other_ip} successfully')
        except (socket.timeout, socket.error):
            messagebox.showwarning('Failure',
                                   f'The message was not sent to {self.other_ip}!, make sure that:\n1) The host has the program running\n2) The host is online\n3) No firewall is blocking the conenction\n4) You have not closed port 5050 (if you did restart the program)')
        finally:
            try:
                s.shutdown(2)
            except:
                pass
            finally:
                s.close()

    def get_data(self):
        gather = self.gather_data
        self.gather_data = ""
        return gather

    def run(self):
        """activating the thread"""

        self.listen()

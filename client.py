from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
from tkinter import *
import utils


start = 1
encryptionType = "rc4"


def receive():
    """Handles receiving of messages."""
    while True:
        try:
            msg = client_socket.recv(BUFSIZ).decode("utf8")
            print(msg)
            msg_list.insert('end', msg)
        except OSError:
            break


def send(event=None):  # event is passed by binders.
    global start
    msg = my_msg.get()
    key = my_key.get()
    my_msg.set("")  # Clears input field.
    if start != 1:
        encryptionType = clicked.get()
        msg = utils.encryption(msg, key, cipher=encryptionType)
        msg = f"{msg}#{key}#{encryptionType}"
    client_socket.send(bytes(msg, "utf8"))
    if msg == "{quit}":
        client_socket.close()
        top.quit()
    start = 0


def on_closing(event=None):
    """This function is to be called when the window is closed."""
    global start
    my_msg.set("{quit}")
    start = 1
    send()


def get_key(event=None):
    key = my_key.get()
    my_key.set("")


top = tkinter.Tk()
top.title("Chat On!")
messages_frame = tkinter.Frame(top)
my_key = tkinter.StringVar()
my_key.set("")
my_msg = tkinter.StringVar()  # For the messages to be sent.
my_msg.set("")
# To see through previous messages.
scrollbar = tkinter.Scrollbar(messages_frame)
# this will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=15,
                           width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()
# w = tkinter.Label(top, text="Encryption key :")
# w.pack()
# key_field = tkinter.Entry(top, textvariable=my_key)
# key_field.bind("<Return>", get_key)
# key_field.pack()
message = tkinter.Label(top, text="Enter plaintext:")
message.pack()
entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()

# CIPHER OPTIONS AVAILABLE TO THE USER
options = [
    "rabin",
]
clicked = StringVar()
clicked.set("rabin")
drop = OptionMenu(top, clicked, *options)
drop.pack()


gap = tkinter.Label(top, text=" ")
gap.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)


HOST = 'localhost'
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect(ADDR)

receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()  # for start of GUI  Interface

"""
This file contains the class which is used to create a GUI for the client.
"""

from queue import Queue

try:
    # for Python2
    from Tkinter import *
    from Tkinter.font import Font
except ImportError:
    # for Python3
    from tkinter import *
    from tkinter.font import Font

import time
from src.packets.packets import ChatTypes, CommandTypes


class MainWindow(object):
    """
    GUI window with a prompt and different windows.
    """
    def __init__(self, gui_input: Queue, gui_output: Queue, title: str, root=None):
        # Set initial state and the title of the GUI.
        self.root = root or Tk()
        self.root.title(title)
        # Set the size of the GUI to a fixed size.
        self.root.resizable(False, False)
        self.quit_state = False
        self.line = ''
        self.nickname = ""
        self.created_room = False
        self.pressed_refresh = False
        self.selected_server = -2

        self.gui_input_queue = gui_input
        self.gui_output_queue = gui_output

        # Create frames, which are different windows in GUI.
        self.f1 = Frame(root)
        self.f2 = Frame(root)
        self.f3 = Frame(root)
        self.f4 = Frame(root)

        normal_font = Font(family='Calibris', size=12)

        # Initialize the frames.
        self.frames = [self.f1, self.f2, self.f3, self.f4]
        for frame in self.frames:
            frame.grid(row=0, column=0, sticky='news')

        self.current_frame = self.f1

        # Create textboxes to set the name of the user
        label_1 = Label(self.f1, text="Select a room and create a nickname")
        label_1.config(font=('Calibris', 16))
        label_1.pack()
        self.e = Entry(self.f1)
        self.e.configure(font=normal_font)
        self.e.focus_set()
        self.e.pack()

        self.btn_refresh = Button(self.f1, text='Refresh', command=self.refresh)
        self.btn_refresh.config(height=4, width=20)
        self.btn_refresh.pack(side=BOTTOM)

        # Make a textbox with scrollbar.
        scrolly = Scrollbar(self.f2)
        scrolly.pack(side=RIGHT, fill=Y)
        self.txt_log = Text(self.f2)

        # Change size of the GUI here.
        self.txt_log.config(width=70, height=30)
        self.txt_log.config(state='disabled')
        self.txt_log.configure(font=normal_font)
        self.txt_log.pack(fill=BOTH)
        scrolly.config(command=self.txt_log.yview)
        self.txt_log.config(yscrollcommand=scrolly.set)

        # Make buttons for shortcuts.
        self.prompt = Entry(self.f2)
        self.prompt.configure(font=normal_font)
        self.prompt.pack(expand=1, fill=X)

        btn_ok = Button(self.f2, text='Ok', command=self.submit)
        btn_clear = Button(self.f2, text='Clear', command=self.clear)
        btn_quit = Button(self.f2, text='Quit', fg='red', command=self.quit)
        btn_back = Button(self.f2, text='Back', command=self.back)
        btn_ok.pack(side=RIGHT)
        btn_clear.pack(side=RIGHT)
        btn_quit.pack(side=LEFT)
        btn_back.pack(side=LEFT)

        # Assign key shortcuts.
        self.root.bind('<Return>', lambda e, b=btn_ok: b.invoke(), add="+")
        self.root.bind('<Escape>', lambda e, b=btn_quit: b.invoke())

        # Create buttons to go to the next frame.
        self.x = Button(self.f1, text='Go to chat', state=DISABLED, command=self.join_chat)
        self.x.pack()

        # Assign more key binds
        self.root.bind('<Return>', lambda e, b=self.x: b.invoke(), add="+")

        self.raise_frame(self.f1)

    def back(self):
        """
        Go back to the first frame.
        """
        self.gui_output_queue.put((CommandTypes.BACK, None))
        self.raise_frame(self.f1)

    def refresh(self):
        """
        Refresh command to search for other nodes.
        """
        self.pressed_refresh = True
        self.gui_output_queue.put((CommandTypes.REFRESH, None))
        self.btn_refresh['state'] = 'disabled'

    def join_chat(self):
        """
        See if a user can join chat then go to second frame.
        """
        if self.current_frame != self.f1:
            return

        self.gui_output_queue.put((CommandTypes.CONNECT, (self.selected_server, self.nickname)))
        self.raise_frame(self.f2)

    def quit(self):
        """
        Disables updates.
        """
        self.quit_state = True

    def submit(self):
        """
        Submits the prompt text and clears the prompt.
        """
        self.line = self.prompt.get()
        self.prompt.delete(0, END)

    def raise_frame(self, frame):
        """
        Raise up the next frame, also set the current_frame.
        """
        self.current_frame = frame
        frame.tkraise()

    def give_time(self):
        """
        This method returns the current local time, like gmtime.
        """
        return "[" + time.strftime("%H:%M:%S", time.localtime()) + "]"

    def getline(self):
        """
        Get the prompt text.
        Returns an empty string if the prompt is empty.
        """
        line, self.line = self.line, ''
        return line

    def write(self, text, username=None):
        """
        Writes a string to the text box.
        """
        if username is None:
            username = self.nickname
        self.txt_log.config(state='normal')
        txt = self.give_time() + " " + username + ": " + text
        self.txt_log.insert(END, txt)
        self.txt_log.yview(END)
        self.txt_log.config(state='disabled')

    def writeln(self, text, username=None):
        """
        Writes a string to the text box followed by a newline.
        """
        self.write('%s\n' % text, username)

    def write_network(self, usernames):
        """
        Writes the list of the nodes of the network to the GUI.
        """
        if not usernames:
            self.writeln('No nodes in network.', 'SYSTEM')
        else:
            self.writeln('Network nodes:', 'SYSTEM')

        for key, value in usernames.items():
            self.writeln('Mac addres - Username', 'SYSTEM')
            self.writeln('%s - %s' % (key, value), 'SYSTEM')

    def clear(self):
        """
        Clears the text box.
        """
        self.txt_log.config(state='normal')
        self.txt_log.delete(0.0, END)
        self.txt_log.config(state='disabled')

    def update(self):
        """
        Updates the window state.
        Returns True on success or False to indicate
        the application should quit.
        """
        if self.quit_state:
            return False
        self.root.update()

        # Making sure your CPU does not overheat.
        time.sleep(1 / 60)
        return True

    def select_server(self, index):
        self.selected_server = index

    def update_nodes(self, lst):
        """
        Create a list of radio buttons to select a server to join.
        :param lst: list of available servers.
        """
        def create_closure(_val):
            return lambda: self.select_server(_val)

        self.selected_server = -1

        if not self.created_room:
            Radiobutton(self.f1, text='Create room', indicatoron=0, width=30, padx=30, command=create_closure(-1)).pack()
            self.created_room = True

        for val, node in enumerate(lst):
            Radiobutton(self.f1,
                        text=node,
                        indicatoron=0,
                        width=30,
                        padx=30,
                        value=val,
                        command=create_closure(val)).pack()

    def handle_chat(self, packet):
        """
        Perform correct action in the GUI for a command from a user.
        :param packet: bundle of data containing the action.
        """
        if packet:
            chat_type, data = packet
            if chat_type == ChatTypes.NODES:
                self.update_nodes(data)
            elif chat_type == ChatTypes.NETWORK or chat_type == ChatTypes.NETWORK:
                self.write_network(data)
            elif chat_type == CommandTypes.REFRESH:
                self.pressed_refresh = False
                self.btn_refresh['state'] = 'normal'
            else:
                name, message = data
                self.writeln(message, name)

    def run(self):
        """
        Update the chat window to show the chat messages in the text box.
        """
        while self.update():
            # Check if there is input for a nickname.
            if self.e.get():
                if self.current_frame != self.f1:
                    pass
                elif 3 < len(self.e.get()) < 13 and self.selected_server > -2 and not self.pressed_refresh:
                    self.nickname = self.e.get()
                    self.x['state'] = 'normal'
                else:
                    self.x['state'] = 'disabled'

            # Check if there is a message to be send in the chat.
            line = self.getline()
            if line:
                self.writeln(line)
                self.gui_output_queue.put((CommandTypes.GUI, line))

            if not self.gui_input_queue.empty():
                packet = self.gui_input_queue.get()
                self.handle_chat(packet)

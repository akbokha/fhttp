# fhttp - An application which is capable of exploiting techniques such as ARP cache poisoning,
# and which uses the positions acquired by exploiting these vulnerabilities for things such as stealing insecure cookies
# Abdel K. Bokharouss & Adriaan Knapen
# MIT license

import os
import tkFont as tkfont
import tkMessageBox
import webbrowser
from Tkinter import *
from ttk import Notebook

from arp_spoof import ArpSpoof
from network_discoverer import NetworkDiscoverer

__authors__ = "\n".join(['Abdel K. Bokharouss',
                         'Adriaan Knapen'])

# Directories (paths)
script_dir = os.path.dirname(os.path.realpath(__file__))
media_dir = script_dir + os.path.sep + 'media'


class MainApplication(Tk):

    def __init__(self, network_discoverer):
        Tk.__init__(self)
        self.title_font = tkfont.Font(family='Helvetica', size=15, weight='bold', slant='italic')
        self.h2_font = tkfont.Font(family='Helvetica', size=13, weight='bold')
        self.network_discoverer = network_discoverer
        self.own_mac_address = network_discoverer.get_own_mac_address()
        self.own_ip_address = network_discoverer.get_own_ip_address()
        self.configure(background='darkgrey')

        width = int(self.winfo_screenwidth() / 1.5)
        height = int(self.winfo_screenheight() / 1.5)
        x_start = int(self.winfo_screenwidth() / 5)
        y_start = int(self.winfo_screenheight() / 5)
        self.geometry('%dx%d+%d+%d' % (width, height, x_start, y_start))
        self.resizable(0, 0)  # do not feel like dealing with resizable frames
        self.conf_menu_bar()  # configure menu-bar

        img_icon = PhotoImage(file=media_dir + os.path.sep + 'fhttp_logo.ico')
        self.tk.call('wm', 'iconphoto', self._w, img_icon)

        for row in range(0, 100):
            self.rowconfigure(row, weight=1)
            self.columnconfigure(row, weight=1)

        # notebook configuration (tabs)
        notebook = Notebook(self)
        notebook.grid(row=1, column=0, columnspan=100, rowspan=50, sticky='nesw', padx=5)

        # output frame configuration
        self.output = OutputFrame(parent=self)
        self.output.grid(row=53, column=0, columnspan=100, rowspan=45, sticky='nesw', padx=5)

        # notebook frames
        self.tabs = {}
        for tab in (WelcomePage, StartScanPage, ManualInputPage):
            tab_frame_name = tab.__name__
            frame = tab(parent=notebook, controller=self)
            notebook.add(frame, text=tab_frame_name)
            self.tabs[tab_frame_name] = frame

        tkMessageBox.showinfo("fHTTP", "\n\n\nWelcome to fhttp\n\n"
                                       "We inherently trust no one, including each other\n\n\n".ljust(500))

    def conf_menu_bar(self):
        menu_bar = Menu(self)
        # help menu
        help_menu = Menu(menu_bar, tearoff=0)
        help_menu.add_command(label='About', command=self.display_about)
        help_menu.add_command(label='Support and Documentation', command=self.display_support_doc)
        # help_menu.add_separator()
        menu_bar.add_cascade(label='Help', menu=help_menu)

        menu_bar.add_command(label='Exit', command=self.quit)
        self.config(menu=menu_bar)

    @staticmethod
    def display_about():
        tkMessageBox.showinfo("About", "Lorem ipsum dolor sit amet, "
                                       "consectetur adipiscing elit,"
                                       " sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \n\n"
                                       "Abdel K. Bokharouss and Adriaan Knapen \n")

    @staticmethod
    def display_support_doc():
        webbrowser.open('https://github.com/akbokha/fhttp')


class OutputFrame(Frame):

    status = '[status] '
    output = '[output] '

    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.configure(bg='black')
        self.status_message = Message(self, anchor=W, width=1200, text=self.status.__add__('no status to display'))
        self.status_message.config(bg='black', foreground='white')
        self.status_message.pack(side=TOP, anchor=W, fill=X)

        self.output_message = Message(self, anchor=W, width=1200, text=self.output.__add__('no output to display'))
        self.output_message.config(bg='black', foreground='white')
        self.output_message.pack(side=TOP, anchor=W, fill=X)

    def update_status(self, message):
        if type(message) is str:  # single string
            self.status_message = Message(self, text=self.message.__add__(message))
        else:  # to-do: figure out how to handle list/collection of strings in an elegant way
            pass

    def update_output(self, message):
        if type(message) is str:  # single string
            self.output_message = Message(self, text=self.output__add__(message))
        else:  # to-do: figure out how to handle list/collection of strings in an elegant way
            pass


class WelcomePage(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller

        # welcome text start page
        label_welcome = Label(self, text='Welcome to fhttp\n'
                                         'We inherently trust no one, including each other',
                              font=controller.title_font)
        label_welcome.pack(side='top', pady=20)

        button_scan = Button(self, text="Start exploring the local network",
                           command=lambda: controller.show_frame("StartScanPage"))
        button_scan.pack()
        button_manual = Button(self, text="Set victim and target manually",
                        command=lambda: controller.show_frame("ManualInputPage"))
        button_manual.pack()


class StartScanPage(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        label_scan = Label(self, text='Let\'s check who (and what) is connected to our local network',
                           font=controller.h2_font)
        label_scan.pack(side='top', pady=20)
        button_scan = Button(self, text="Scan local network")
        button_scan.pack()


class ManualInputPage(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        self.parent = parent
        label = Label(self, text='Identify the target and victim who need to be spoofed',
                      font=controller.h2_font)
        label.pack(side='top', pady=20)
        label_ip_victim = Label(self, text='Victim IP Address: ').pack()
        entry_ip_victim = Entry(self)
        entry_ip_victim.pack()
        label_ip_target = Label(self, text='Target IP Address: ').pack()
        entry_ip_target = Entry(self)
        entry_ip_target.pack()

        # @todo add a drop down for all all available network interfaces

        button_start_ARP = Button(self, text="Start ARP Spoofing",
                                  command=lambda: self.start_spoofing(entry_ip_victim.get(), entry_ip_target.get()))
        button_start_ARP.pack()

    @staticmethod
    def start_spoofing(vIP, tIP):
        arp = ArpSpoof(vIP, tIP)
        arp.start()


def main():
    network_discoverer = NetworkDiscoverer()
    # test_ip_mac_pair = network_discoverer.get_ip_to_mac_mapping(True).get_all()
    init_gui(network_discoverer)


def init_gui(network_discoverer):
    main_app = MainApplication(network_discoverer)
    main_app.mainloop()


if __name__ == '__main__':
    main()

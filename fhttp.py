# fhttp - An application which is capable of exploiting techniques such as ARP cache poisoning,
# and which uses the positions acquired by exploiting these vulnerabilities for things such as stealing insecure cookies
# Abdel K. Bokharouss & Adriaan Knapen
# MIT license

import os
import webbrowser

from Tkinter import *
import tkMessageBox
import tkFont as tkfont

import arp_spoof
from packet_handler.packet_sniffer import PacketSniffer

__authors__ = "\n".join(['Abdel K. Bokharouss',
                         'Adriaan Knapen'])

# Directories (paths)
script_dir = os.path.dirname(os.path.realpath(__file__))
media_dir = script_dir + os.path.sep + 'media'

threads = []


class MainApplication(Tk):

    def __init__(self):
        Tk.__init__(self)
        self.title_font = tkfont.Font(family='Helvetica', size=15, weight='bold', slant='italic')
        self.h2_font = tkfont.Font(family='Helvetica', size=13, weight='bold')

        width = self.winfo_screenwidth() / 2
        height = self.winfo_screenheight() / 2
        x_start = self.winfo_screenwidth() / 4
        y_start = self.winfo_screenheight() / 4
        self.geometry('%dx%d+%d+%d' % (width, height, x_start, y_start))
        self.resizable(0, 0)  # do not feel like dealing with resizable frames

        img_icon = PhotoImage(file=media_dir + os.path.sep + 'fhttp_logo.ico')
        self.tk.call('wm', 'iconphoto', self._w, img_icon)

        container = Frame(self)
        container.pack(side='top', fill='both', expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.conf_menu_bar()

        # pages of the application
        self.frames = {}
        for page in (WelcomePage, StartScanPage, ManualInputPage):
            page_name = page.__name__
            frame = page(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame('WelcomePage')

    def show_frame(self, page_name):
        frame = self.frames[page_name]
        frame.tkraise()

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

        button_start_ARP = Button(self, text="Start ARP Spoofing",
                                  command=lambda:self.start_spoofing(entry_ip_victim.get(), entry_ip_target.get()))
        button_start_ARP.pack()

    def start_spoofing(self, vIP, tIP):
        arp = arp_spoof.ArpSpoof(vIP, tIP)
        arp.start()


def main():
    # init_gui()
    arp = arp_spoof.ArpSpoof('192.168.56.101', '192.168.56.102')
    arp.scan_local_network()
    http_l = PacketSniffer('192.168.56.103', arp.ip_mac_pairs, 'enp0s3')
    arp.start()
    http_l.start()
    arp.join()
    http_l.join()


def init_gui():
    main_app = MainApplication()
    main_app.mainloop()


if __name__ == '__main__':
    main()
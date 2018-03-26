# fhttp - An application which is capable of exploiting techniques such as ARP cache poisoning,
# and which uses the positions acquired by exploiting these vulnerabilities for things such as stealing insecure cookies
# Abdel K. Bokharouss & Adriaan Knapen
# MIT license

import os
import webbrowser

from Tkinter import *
import tkMessageBox
import tkFont as tkfont
from ttk import Notebook

from arp_spoof import ArpSpoof
from network_discoverer import NetworkDiscoverer
from PacketHandler.packet_sniffer import PacketSniffer

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

        width = int(self.winfo_screenwidth() / 1.5)
        height = int(self.winfo_screenheight() / 1.5)
        x_start = int(self.winfo_screenwidth() / 5)
        y_start = int(self.winfo_screenheight() / 5)
        self.geometry('%dx%d+%d+%d' % (width, height, x_start, y_start))
        self.resizable(0, 0)  # do not feel like dealing with resizable frames

        img_icon = PhotoImage(file=media_dir + os.path.sep + 'fhttp_logo.ico')
        self.tk.call('wm', 'iconphoto', self._w, img_icon)

        for row in range(0, 50):
            self.rowconfigure(row, weight=1)
            self.columnconfigure(row, weight=1)

        notebook = Notebook(self)
        notebook.grid(row=1, column=0, columnspan=50, rowspan=25, sticky='nesw', padx=5, pady=5)

        output = Frame(self, bg='black')
        output.grid(row=25, column=0, columnspan=50, rowspan=24, sticky='nesw', padx=5)

        page1 = Frame(notebook)
        notebook.add(page1, text='Tab1')

        page2 = Frame(notebook)
        notebook.add(page2, text='Tab2')

        # container = Frame(self)
        # container.pack(side='top', fill='both', expand=True)
        # container.grid_rowconfigure(0, weight=1)
        # container.grid_columnconfigure(0, weight=1)
        # self.conf_menu_bar()


def main():
    network_discoverer = NetworkDiscoverer()
    # test_ip_mac_pair = network_discoverer.get_ip_to_mac_mapping(True).get_all()
    init_gui(network_discoverer)


def init_gui(network_discoverer):
    main_app = MainApplication(network_discoverer)
    main_app.mainloop()


if __name__ == '__main__':
    main()
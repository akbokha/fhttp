# fhttp - An application which is capable of exploiting techniques such as ARP cache poisoning,
# and which uses the positions acquired by exploiting these vulnerabilities for things such as stealing insecure cookies
# Abdel K. Bokharouss & Adriaan Knapen
# MIT license

import os
import webbrowser

import arp_spoof
import http_listener
from Tkinter import *
import tkMessageBox

__authors__ = "\n".join(['Abdel K. Bokharouss',
                         'Adriaan Knapen'])

# Directories (paths)
script_dir = os.path.dirname(os.path.realpath(__file__))
media_dir = script_dir + os.path.sep + 'media'


class MainApplication(Frame):

    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        parent.title('fhttp')
        self.close_button = Button(parent, text="Close", command=parent.quit)
        self.close_button.pack()
        self.conf_menu_bar()

    def conf_menu_bar(self):
        menu_bar = Menu(self.parent)

        # help menu
        help_menu = Menu(menu_bar, tearoff=0)
        help_menu.add_command(label='About', command=self.display_about)
        help_menu.add_command(label='Support and Documentation', command=self.display_support_doc)
        # help_menu.add_separator()
        menu_bar.add_cascade(label='Help', menu=help_menu)

        menu_bar.add_command(label='Exit', command=self.parent.quit)
        self.parent.config(menu=menu_bar)

    @staticmethod
    def display_about():
        tkMessageBox.showinfo("About", "Lorem ipsum dolor sit amet, "
                                         "consectetur adipiscing elit,"
                                         " sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \n\n"
                                         "Abdel K. Bokharouss and Adriaan Knapen \n")

    @staticmethod
    def display_support_doc():
        webbrowser.open('https://github.com/akbokha/fhttp')


def main():
    init_gui()
    # arp = arp_spoof.ArpSpoof('192.168.56.101', '192.168.56.102').scan_local_network()
    # arp = arp_spoof.ArpSpoof('192.168.56.101', '192.168.56.102')
    # http_l = http_listener.HttpListener()
    # arp.start()
    # http_l.start()
    # arp.join()
    # http_l.join()


def init_gui():
    root = Tk()
    # frame size
    width = root.winfo_screenwidth() / 2
    height = root.winfo_screenheight() / 2
    x_start = root.winfo_screenwidth() / 4
    y_start = root.winfo_screenheight() / 4
    root.geometry('%dx%d+%d+%d' % (width, height, x_start, y_start))

    # init main application
    MainApplication(root).pack(side='top', fill='both', expand=True,)

    # set frame icon
    img_icon = PhotoImage(file=media_dir + os.path.sep + 'fhttp_logo.ico')
    root.tk.call('wm', 'iconphoto', root._w, img_icon)

    # has to be replace with update_idletasks() + update()
    root.mainloop()


if __name__ == '__main__':
    main()
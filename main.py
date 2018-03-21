import threading as thr
import arp_spoof
import http_listener

if __name__ == '__main__':
    arp = thr.Thread(target=arp_spoof.main())
    http_l = thr.Thread(target=http_listener.main())
    arp.start()
    http_l.start()
    arp.join(); http_listener.join()
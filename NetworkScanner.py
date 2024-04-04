"""
This contains Two functions, 
scan is responsible to send out packages inorder to gain the IP AND MAC of the devices on your network
client_table takes the output returned by scan and display it in a tabular format
"""
import scapy.all as scapy
def scan(ip):
    """
    uses scapy inorder to send out packages from the broadcast mac to the devices on the network , it does by the who has calls 
    you recieve two types of output one being answered and other being unanswered 
    this function only returns info about ANSWERED part 
    """
    #creating a packet
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast=broadcast/arp_request

    answered,unanswered = scapy.srp(arp_request_broadcast,verbose = False ,timeout=1.0)
    
    client_dict = {}
    for i in range(len(answered)):
        client_dict[i+1]=(answered[i][1].psrc,answered[i][1].hwsrc)
    return client_dict
 
def client_table(data):
    """
    Simple function to display the findings in an organized mannner 
    """
    for a,b in data.values():
        print('IP\t\t\tMAC Address')
        print(a+"\t\t"+b)
client_table(scan('192.168.153.1/24'))

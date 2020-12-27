import threading
import scapy 
import socket
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
import queue
import os
if os.name == 'nt':
    import pydivert
    


class IP_CATCH(threading.Thread):
    def __init__(self,addr,rule,queue):
        self.addr = addr
        self.queue = queue
        self.rule = rule
        threading.Thread.__init__(self, name=self.rule+'_CATCH_'+addr)
    def header(self,src,dst):
        my_hex = lambda x : x.to_bytes(((x.bit_length() + 7) // 8),"big").hex()
        src_str = src.split('\.')
    def run(self):
        print(self.name + " is running")
        filter_str = ''
        if self.rule.lower() == "outbound":
            filter_str = self.rule.lower()+" && ip.DstAddr == " + self.addr
        elif self.rule.lower() == "inbound":
            filter_str = self.rule.lower()+" && ip.SrcAddr == " + self.addr
        with pydivert.WinDivert(filter_str) as w:
            for packet in w:
                _bytes = packet.raw.tobytes()
                print("[CATCH]",self.rule,_bytes)
                #a = IP(_bytes)
                #print(a)
                #scapy.sendrecv.send(a)
                self.queue.put(_bytes)
                #w.send(packet)

                
class IP_SPOOF(threading.Thread):
    def __init__(self,addr,rule,queue):
        
        self.queue = queue
        self.rule = rule
        self.addr = addr
        threading.Thread.__init__(self, name=self.rule+'_SPOOF_'+addr)
        
    def run(self):
        print(self.name + " is running")
        while True:
            try:
                data = self.queue.get(False)
            except queue.Empty:
                pass
            else:
                pkt = IP(data)
                #Direction.OUTBOUND
                if self.rule == "OUTBOUND":
                    print(pkt)
                    pkt[IP].src = self.addr 
                    print("[SPOOF]>>>>>>>>",pkt)
                    
                if self.rule == "INBOUND":
                    pkt[IP].dst = self.addr
                    print("[SPOOF]<<<<<<<<",pkt)
                scapy.sendrecv.send(pkt)

                
class ICMP_IN(threading.Thread):
    def __init__(self,addr,queue):
        self.addr = addr
        self.queue = queue
        threading.Thread.__init__(self, name='ICMP_IN_'+addr)
        
    def run(self):
        print(self.name + " is running")
        with pydivert.WinDivert("inbound && icmp && ip.SrcAddr == " + self.addr) as w:
            for packet in w:
                data = packet.icmpv4.payload
                print("<<<<"+self.addr+"<<<<",data)
                self.queue.put(data)
                
class ICMP_OUT(threading.Thread):
    def __init__(self,addr,queue):
        self.addr = addr
        self.queue = queue
        threading.Thread.__init__(self, name='ICMP_OUT_'+addr)
    def calculate_checksum(self,source_string):
        """
        A port of the functionality of in_cksum() from ping.c
        Ideally this would act on the string as a series of 16-bit ints (host
        packed), but this works.
        Network data is big-endian, hosts are typically little-endian
        """
        countTo = (int(len(source_string) / 2)) * 2
        sum = 0
        count = 0

        # Handle bytes in pairs (decoding as short ints)
        loByte = 0
        hiByte = 0
        while count < countTo:
            if (sys.byteorder == "little"):
                loByte = source_string[count]
                hiByte = source_string[count + 1]
            else:
                loByte = source_string[count + 1]
                hiByte = source_string[count]
            if not six.PY3:
                loByte = ord(loByte)
                hiByte = ord(hiByte)
            sum = sum + (hiByte * 256 + loByte)
            count += 2

        # Handle last byte if applicable (odd-number of bytes)
        # Endianness should be irrelevant in this case
        if countTo < len(source_string): # Check for odd length
            loByte = source_string[len(source_string) - 1]
            if not six.PY3:
                loByte = ord(loByte)
            sum += loByte

        sum &= 0xffffffff # Truncate sum to 32 bits (a variance from ping.c, which
                          # uses signed ints, but overflow is unlikely in ping)

        sum = (sum >> 16) + (sum & 0xffff)   # Add high 16 bits to low 16 bits
        sum += (sum >> 16)               # Add carry from above (if any)
        answer = ~sum & 0xffff            # Invert and truncate to 16 bits
        answer = socket.htons(answer)

        return answer
    def send_one_ping(self, data):
        socket_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
      # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        checksum = 0
        own_id = os.getpid() & 0xFFFF
      # Make a dummy header with a 0 checksum.
        header = struct.pack(
            "!BBHHH", 8, 0, checksum, own_id,0
        )

      # Calculate the checksum on the data and the dummy header.
        checksum = self.calculate_checksum(header + data) # Checksum is in network order

      # Now that we have the right checksum, we put that in. It's just easier
      # to make up a new header than to stuff it into the dummy.
        header = struct.pack(
            "!BBHHH", 8, 0, checksum, own_id, 0
        )

        packet = header + data

        try:
            socket_icmp.sendto(packet, (self.addr, 1)) # Port number is irrelevant for ICMP
        except socket.error as e:
            self.response.output.append("General failure (%s)" % (e.args[1]))
            socket_icmp.close()
            return False
        return True
        
    def run(self):
        print(self.name + " is running")
        while True:
            try:
                data = self.queue.get_nowait()
            except queue.Empty:
                pass
            else:
                print(">>>>"+self.addr+">>>>",data)
                self.send_one_ping(data)

                
class TCP_IN(threading.Thread):
    def __init__(self,queue,socket=None,conn=None,open_socket=False):
        self.socket = socket
        self.conn = conn
        self.queue = queue
        self.open_socket = open_socket
        threading.Thread.__init__(self, name='TCP_IN_')
        
    def listen_conn(self):
        while True:
            data = self.conn.recv(2**16)
            print("[TCP]<<<<<<<<",data)
            self.queue.put(data)
    def listen_socket(self):
        while True:
            data = self.socket.recv(2**16)
            print("[TCP]<<<<<<<<",data)
            self.queue.put(data)
    def run(self):
        print(self.name + " is running")
        if self.open_socket:
            self.listen_conn()
        else:
            self.listen_socket()
        
class TCP_OUT(threading.Thread):
    def __init__(self,queue,socket=None,conn=None,open_socket=False):
        self.socket = socket
        self.conn = conn
        self.queue = queue
        self.open_socket = open_socket
        threading.Thread.__init__(self, name='TCP_OUT_')
        
    def conn_send(self):
        print(self.name + " is running")
        while True:
            try:
                data = self.queue.get(False)
            except queue.Empty:
                pass
            else:
                print("[TCP]>>>>>>>>",data)
                self.conn.sendall(data)
                
    def socket_send(self):
        print(self.name + " is running")
        while True:
            try:
                data = self.queue.get(False)
            except queue.Empty:
                pass
            else:
                print("[TCP]>>>>>>>>",data)
                self.socket.sendall(data)
    def run(self):
        if self.open_socket:
            self.conn_send()   
        else:
            self.socket_send()      

def TCP_route(addr,port,queue_in,queue_out,open_socket = False):
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if open_socket:
        tcp_socket.bind(('0.0.0.0', port))
        tcp_socket.listen()
        tcp_socket_opt = tcp_socket.setsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        print("waiting connection..")
        conn, c_addr = tcp_socket.accept()
        print("[tcp connected]",c_addr)
        tcp_out = TCP_OUT(conn=conn,queue = queue_out,open_socket=open_socket)
        tcp_in = TCP_IN(conn=conn,queue = queue_in,open_socket=open_socket)
            
    else:
        tcp_socket.connect((addr, port))
        tcp_out = TCP_OUT(socket=tcp_socket,queue = queue_out,open_socket=open_socket)
        tcp_in = TCP_IN(socket=tcp_socket,queue = queue_in,open_socket=open_socket)
    return tcp_in,tcp_out

class Node_Connection:
    def __init__(self,addr,protocol,send_queue,input_queue):
        self.addr = addr
        self.send_queue = send_queue
        self.input_queue = input_queue
        self.protocol = protocol
        threading.Thread.__init__(self, name="CON_"+protocol + "_" + addr )
        self.build()
    def build(self):
        if self.protocol == 'TCP':
            self.port = int(input("port: "))
            self.open_socket = input("host server?(y/n): ").upper() == 'Y'
            self.thread_in, self.thread_out = TCP_route(self.addr,self.port,self.input_queue,self.send_queue,self.open_socket)
        elif self.protocol == 'ICMP':
            icmp_out = ICMP_OUT(addr=self.addr,queue = self.send_queue)
            icmp_in = ICMP_IN(addr=self.addr, queue = self.input_queue)
            self.thread_in, self.thread_out =icmp_in,icmp_out

    def start(self):
        self.thread_in.start()
        self.thread_out.start()

def pc101():
    A_B = queue.Queue()
    B_A = queue.Queue()
    
    #addr1 = input("node(1) ip address: ")
    addr1 = "192.168.123.100"
    #proto1 = input("node(1) protocol(icmp/tcp): ").upper()
    proto1 = "TCP"
    node1 = Node_Connection(addr1,proto1,A_B,B_A)
    #addr2 = input("node(2) ip address: ")
    addr2 = '61.99.15.105'
    #proto2 = input("node(2) protocol(icmp/tcp): ").upper()
    proto2 = 'TCP'
    node2 = Node_Connection(addr2,proto2,B_A,A_B)
    
    node1.start()
    node2.start()
    
def pc05():
    A_B = queue.Queue()
    B_A = queue.Queue()
    
    #addr1 = input("node(1) ip address: ")
    addr1 = "192.168.0.8"
    #proto1 = input("node(1) protocol(icmp/tcp): ").upper()
    proto1 = "ICMP"
    node1 = Node_Connection(addr1,proto1,A_B,B_A)
    #addr2 = input("node(2) ip address: ")
    addr2 = '218.239.28.198'
    #proto2 = input("node(2) protocol(icmp/tcp): ").upper()
    proto2 = 'TCP'
    node2 = Node_Connection(addr2,proto2,B_A,A_B)
    
    node1.start()
    node2.start()
    
def pc08():
    A_B = queue.Queue()
    B_A = queue.Queue()
    
    #addr1 = input("node(1) ip address: ")
    addr1 = "218.239.28.198"
    #proto1 = input("node(1) protocol(icmp/tcp): ").upper()
    proto1 = "TCP"
    node1 = Node_Connection(addr1,proto1,A_B,B_A)
    #addr2 = input("node(2) ip address: ")
    #proto2 = input("node(2) protocol(icmp/tcp): ").upper()
    ip_catch = IP_CATCH('192.168.0.5',"INBOUND",A_B)
    ip_spoof = IP_SPOOF('192.168.0.8',"OUTBOUND",B_A)
    node1.start()
    ip_spoof.start()
    ip_catch.start()

def pc100():
    A_B = queue.Queue()
    B_A = queue.Queue()
    
    #addr1 = input("node(1) ip address: ")
    addr1 = "0.0.0.0"
    #proto1 = input("node(1) protocol(icmp/tcp): ").upper()
    proto1 = "TCP"
    node1 = Node_Connection(addr1,proto1,A_B,B_A)
    #addr2 = input("node(2) ip address: ")
    ip_catch = IP_CATCH('192.168.0.5',"OUTBOUND",A_B)
    ip_spoof = IP_SPOOF('192.168.123.100',"INBOUND",B_A)
    
    node1.start()
    ip_catch.start()
    ip_spoof.start()
def pub():
    A_B = queue.Queue()
    B_A = queue.Queue()
    
    #addr1 = input("node(1) ip address: ")
    addr1 = "192.168.123.100"
    #proto1 = input("node(1) protocol(icmp/tcp): ").upper()
    proto1 = "tcp"
    node1 = Node_Connection(addr1,proto1,A_B,B_A)
    #addr2 = input("node(2) ip address: ")
    addr2 = '192.168.123.105'
    #proto2 = input("node(2) protocol(icmp/tcp): ").upper()
    proto2 = 'icmp'
    node2 = Node_Connection(addr2,proto2,B_A,A_B)
    
    node1.start()
    node2.start()
    
if __name__ == '__main__':
    pc100() 

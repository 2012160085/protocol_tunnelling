import threading
from scapy.all import*  
import socket
from scapy.layers.inet import IP
import pydivert
import queue




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

        sum = (sum >> 16) + (sum & 0xffff)	# Add high 16 bits to low 16 bits
        sum += (sum >> 16)					# Add carry from above (if any)
        answer = ~sum & 0xffff				# Invert and truncate to 16 bits
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
    def __init__(self,socket,queue):
        self.socket = socket
        self.queue = queue
        threading.Thread.__init__(self, name='TCP_IN_')
        
    def open_socket(self):
        while True:
            data = self.socket.recv(2**16)
            print("[TCP]<<<<<<<<",data)
            self.queue.put(data)
    def run(self):
        print(self.name + " is running")
        self.open_socket()
        
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
        conn, c_addr = s.accept()
        print("[tcp connected]",c_addr)
        tcp_out = TCP_OUT(conn=self.conn,queue = A_B)
            
    else:
        tcp_socket.connect((addr, port))
        tcp_out = TCP_OUT(socket=tcp_socket,queue = A_B)
    tcp_in = TCP_IN(socket=tcp_socket,queue = B_A)
    tcp_in.start()
    tcp_out.start()
        
if __name__ == '__main__':
    A_B = queue.Queue()
    B_A = queue.Queue()
    TCP_route('192.168.123.105',81,B_A,A_B)
    icmp_out = ICMP_OUT(addr='192.168.123.105',queue = B_A)
    icmp_in = ICMP_IN(addr='192.168.123.105', queue = A_B)
    input()

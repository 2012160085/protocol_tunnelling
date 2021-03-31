
import configparser
import progressbar
import threading
import time
import scapy 
import socket
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.layers.inet import UDP
from scapy.layers.l2 import Ether
import struct
import queue
import sys
import os
if os.name == 'nt':
    import pydivert
    


class IP_CATCH(threading.Thread):
    def __init__(self,addr,rule,queue):
        self.addr = addr
        self.queue = queue
        self.rule = rule
        threading.Thread.__init__(self, name=self.rule[:-5]+'_CATCH_')
    def header(self,src,dst):
        my_hex = lambda x : x.to_bytes(((x.bit_length() + 7) // 8),"big").hex()
        src_str = src.split('\.')
    def run(self):
        print("thread start/ " + self.name)
        filter_str = self.rule.lower() + " && (" + self.addr + ")"
        print("catch filter/",filter_str)
        with pydivert.WinDivert(filter_str) as w:
            for packet in w:
                _bytes = packet.raw.tobytes()
                #print("[CATCH]",self.rule,_bytes.hex())
                while True:
                    piece = _bytes[:1000]
                    _bytes = _bytes[1000:]
                    if len(_bytes) > 0:
                        self.queue.put(b'+'+piece)
                    else:
                        self.queue.put(b'-'+piece)
                        break
                    

                
class IP_SPOOF(threading.Thread):
    def __init__(self,addr,rule,queue):
        
        self.queue = queue
        self.rule = rule
        self.addr = addr
        self.msg = b''
        threading.Thread.__init__(self, name=self.rule[:-5]+'_SPOOF_')
        
    def run(self):
        print("thread start/ " + self.name)
        while True:
            try:
                data = self.queue.get(False)
            except queue.Empty:
                pass
            else:
                #print('[SPOOF]',self.rule,data.hex())
                if data[:1] ==  b'+':
                    self.msg = self.msg + data[1:]
                elif data[:1] == b'-':
                    self.msg = self.msg + data[1:]
                    pkt = IP(self.msg)
                    #Direction.OUTBOUND
                    if self.rule == "OUTBOUND":
                        #print(pkt)
                        pkt[IP].src = self.addr 
                        #print("[SPOOF]>>>>>>>>",pkt)
                        
                    if self.rule == "INBOUND":
                        pkt[IP].dst = self.addr
                        #print("[SPOOF]<<<<<<<<",pkt)
                    pkt[IP].chksum = None
                    try:
                        pkt[TCP].chksum = None
                    except:
                        pass
                    try:
                        pkt[UDP].chksum = None
                    except:
                        pass
                    try:
                        pkt[ICMP].chksum = None
                    except:
                        pass
                    #pkt.show2()
                    scapy.sendrecv.send(pkt,verbose=False)
                    self.msg = b''

                
class ICMP_IN(threading.Thread):
    def __init__(self,addr,queue,stat):
        self.addr = addr
        self.queue = queue
        self.stat = stat
        threading.Thread.__init__(self, name='IN_ICMP_')
        
    def run(self):
        print("thread start/ " + self.name)
        with pydivert.WinDivert("inbound && icmp && ip.SrcAddr == " + self.addr) as w:
            for packet in w:
                data = packet.icmpv4.payload[4:]
                #print("[ICMP]","INBOUND",data.hex())
                self.queue.put(data)
                self.stat.queue[0] = self.stat.queue[0] + len(data)
class ICMP_OUT(threading.Thread):
    def __init__(self,addr,queue,stat):
        self.addr = addr
        self.queue = queue
        self.stat = stat
        threading.Thread.__init__(self, name='OUT_ICMP_')
    def calculate_checksum(self,source_string):

        countTo = (int(len(source_string) / 2)) * 2
        sum = 0
        count = 0
        loByte = 0
        hiByte = 0
        while count < countTo:
            if (sys.byteorder == "little"):
                loByte = source_string[count]
                hiByte = source_string[count + 1]
            else:
                loByte = source_string[count + 1]
                hiByte = source_string[count]
            sum = sum + (hiByte * 256 + loByte)
            count += 2

       
        if countTo < len(source_string):
            loByte = source_string[len(source_string) - 1]
            sum += loByte

        sum &= 0xffffffff 
                         

        sum = (sum >> 16) + (sum & 0xffff)   
        sum += (sum >> 16)               
        answer = ~sum & 0xffff            
        answer = socket.htons(answer)

        return answer
    def send_one_ping(self, data):
        socket_icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))

        checksum = 0
        own_id = os.getpid() & 0xFFFF
  
        header = struct.pack(
            "!BBHHH", 8, 0, checksum, own_id,0
        )

   
        checksum = self.calculate_checksum(header + data) 

        header = struct.pack(
            "!BBHHH", 8, 0, checksum, own_id, 0
        )

        packet = header + data

        try:
            socket_icmp.sendto(packet, (self.addr, 1)) # 아무포트
        except socket.error as e:
            self.response.output.append("General failure (%s)" % (e.args[1]))
            socket_icmp.close()
            return False
        return True
        
    def run(self):
        print("thread start/ " + self.name)
        while True:
            try:
                data = self.queue.get_nowait()
            except queue.Empty:
                pass
            else:
                #print("[ICMP]","OUTBOUND",data.hex())
                self.send_one_ping(data)
                self.stat.queue[0] = self.stat.queue[0] + len(data)
                
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
            #print("[TCP]<<<<<<<<",data)
            self.queue.put(data)
    def listen_socket(self):
        while True:
            data = self.socket.recv(2**16)
            #print("[TCP]<<<<<<<<",data)
            self.queue.put(data)
    def run(self):
        print("thread start/ " + self.name)
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
        print("thread start/ " + self.name)
        while True:
            try:
                data = self.queue.get(False)
            except queue.Empty:
                pass
            else:
                #print("[TCP]>>>>>>>>",data)
                self.conn.sendall(data)
                
    def socket_send(self):
        print(self.name + " 스레드 실행")
        while True:
            try:
                data = self.queue.get(False)
            except queue.Empty:
                pass
            else:
                #print("[TCP]>>>>>>>>",data)
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
    def __init__(self,addr,protocol,send_queue,input_queue,in_stat,out_stat):
        self.addr = addr
        self.send_queue = send_queue
        self.input_queue = input_queue
        self.protocol = protocol
        self.in_stat = in_stat
        self.out_stat = out_stat
        threading.Thread.__init__(self, name="CON_"+protocol + "_" + addr )
        self.build()
    def build(self):
        if self.protocol == 'TCP':
            self.port = int(input("port: "))
            self.open_socket = input("host server?(y/n): ").upper() == 'Y'
            self.thread_in, self.thread_out = TCP_route(self.addr,self.port,self.input_queue,self.send_queue,self.open_socket)
        elif self.protocol == 'ICMP':
            icmp_out = ICMP_OUT(addr=self.addr,queue = self.send_queue, stat = self.in_stat)
            icmp_in = ICMP_IN(addr=self.addr, queue = self.input_queue, stat = self.out_stat)
            self.thread_in, self.thread_out =icmp_in,icmp_out

    def start(self):
        self.thread_in.start()
        self.thread_out.start()
        
class STATUS_VIEWER:
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

def get_input(msg,mapping):
    print(msg,end='')
    key = input()
    while key not in mapping:
        print(msg,end='')
        key = input()
    return mapping[key]
def pc100():
    in_stat = queue.Queue()
    out_stat = queue.Queue()
    in_stat.put(0)
    out_stat.put(0)
    RUN_MODE = get_input("\n---------------------\n      SELECT MODE\n---------------------\n[CLIENT:1] [DELEGATOR:2] : ",{'1':'CLIENT','2':'DELEGATER'})   
    config = configparser.ConfigParser()

        
    print("===================================")
    print("    ____________  _______          \n   /  _/ ____/  |/  / __ \\         \n   / // /   / /|_/ / /_/ /         \n _/ // /___/ /  / / ____/          \n/___/\\____/_/__/_/_/_   __________ \n /_  __/ / / / | / / | / / ____/ / \n  / / / / / /  |/ /  |/ / __/ / /  \n / / / /_/ / /|  / /|  / /___/ /___\n/_/  \\____/_/ |_/_/ |_/_____/_____/\n                                   ")  
    print("===================================")

    config.read('tunnel.ini',encoding='UTF8')
    A_B = queue.Queue()
    B_A = queue.Queue()
    STAT = queue.Queue()
    proto1 = "ICMP"
    if RUN_MODE == 'CLIENT':
        ip_arr = config.get(RUN_MODE,'FILTER')
        print('[SETTING]')
        print('target count:', len(ip_arr))
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        TARGET_IP_ADDR = ip_arr
        MY_IP_ADDR = local_ip
        print("local ip:",local_ip)
        NODE_IP_ADDR = config.get(RUN_MODE,'DELE_IP')
        print("delegator ip:",NODE_IP_ADDR)
        print("===================================")
        time.sleep(0.3)
        
        addr1 = NODE_IP_ADDR
        node1 = Node_Connection(addr1,proto1,A_B,B_A,in_stat,out_stat)
        #addr2 = input("node(2) ip address: ")
        #해당주소로 나가는 패킷을 아웃큐에 넣음
        ip_catch = IP_CATCH(TARGET_IP_ADDR,"OUTBOUND",A_B)
        #인큐에 있는 패킷의 dst를 해당주소로 변경
        ip_spoof = IP_SPOOF(MY_IP_ADDR,"INBOUND",B_A)
        node1.start()
        time.sleep(0.1)
        ip_spoof.start()
        time.sleep(0.1)
        ip_catch.start()
        last_in = 0
        last_out= 0
        time.sleep(2)
        while True:
            now_in = in_stat.queue[0]
            now_out = out_stat.queue[0]
            msg = "\rUsage(B/s) [UP=" + str((now_in-last_in)/4) + "] [DOWN=" + str((now_out-last_out)/4) + "]                                        "
            last_in = now_in
            last_out = now_out
            sys.stdout.write(msg)
            sys.stdout.flush()
            time.sleep(4)
    else:
        ip_arr = config.get(RUN_MODE,'FILTER')
        print('target count:', len(ip_arr))
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        TARGET_IP_ADDR = ip_arr
        MY_IP_ADDR = local_ip
        print("local ip:",local_ip)
        NODE_IP_ADDR = config.get(RUN_MODE,'CLIENT_IP')
        print("client ip:",NODE_IP_ADDR)
        print("===================================")
        time.sleep(0.3)
        
        addr1 = NODE_IP_ADDR
        node1 = Node_Connection(addr1,proto1,A_B,B_A,in_stat,out_stat)
        #addr2 = input("node(2) ip address: ")
        #해당주소로 나가는 패킷을 아웃큐에 넣음
        ip_catch = IP_CATCH(TARGET_IP_ADDR,"INBOUND",A_B)
        #인큐에 있는 패킷의 dst를 해당주소로 변경
        ip_spoof = IP_SPOOF(MY_IP_ADDR,"OUTBOUND",B_A)
        node1.start()
        time.sleep(0.1)
        ip_spoof.start()
        time.sleep(0.1)
        ip_catch.start()
        last_in = 0
        last_out= 0
        time.sleep(2)
        while True:
            now_in = in_stat.queue[0]
            now_out = out_stat.queue[0]
            msg = "\rUsage(B/s) [UP=" + str(now_in-last_in) + "] [DOWN=" + str(now_out-last_out) + "]                                        "
            last_in = now_in
            last_out = now_out
            sys.stdout.write(msg)
            sys.stdout.flush()
            time.sleep(1)
if __name__ == '__main__':
    try:
        os.chdir(os.getcwd())
        pc100() 
    except Exception as e:
        print(e)
    input()

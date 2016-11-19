import logging
import struct
import socket
import binascii


error_check=False
def print_help(errmsg):
	
   	global error_check
   	if 'Configuration_file' in errmsg:
   		print "Missing Configuration File"
   		return

   	if "Ipaddress" in errmsg:
   		print "Missing IP address"
   		return

   	error_check=True
   	print errmsg



def make_ip_header(src_ip,dest_ip):
   logger=logging.getLogger("Knocker.make_ip_header")
   logger.debug("Source Ip="+src_ip)
   logger.debug("Destination Ip="+dest_ip)
   version=4
   header_length=5
   vers_head_len=int((bin(version)[2:].zfill(4))+(bin(header_length)[2:].zfill(4)),2)
   tos=0
   total_length=50
   identification=4545
   frag=0
   ttl=64
   proto_iden=6
   cheksum=0
   src_ip=socket.inet_aton(src_ip)
   dest_ip=socket.inet_aton(dest_ip)
   #logger.debug("Source IP(Pack)="+binascii.hexlify(src_ip))
   #logger.debug("Destination IP(Pack)="+binascii.hexlify(dest_ip))
   ip_header=struct.pack('>BBHHHBBH4s4s',vers_head_len,tos,total_length,identification,frag,ttl,proto_iden,cheksum,src_ip,dest_ip)
   #logger.debug("IP-header="+binascii.hexlify(ip_header))
   logger.debug("Unpacked Ip_header="+str(struct.unpack('>BBHHHBBH4s4s',ip_header)))
   
   return ip_header

def make_tcp_header(src_ip,dest_ip,sqn,dest_port):
   logger=logging.getLogger("Knocker.make_tcp_header")
   src_port=1234;
   ack=0;
   header_length=5
   reserved=0
   control_urg=0
   control_ack=0
   control_psh=0
   control_rst=0
   control_syn=1
   control_fin=0
   control_flag=bin(control_urg)[2:]+bin(control_ack)[2:]+bin(control_psh)[2:]+bin(control_rst)[2:]+bin(control_syn)[2:]+bin(control_fin)[2:]
   window_size=4500
   checksum=0
   urgent_ptr=0
   hed_res_ctrl=int((bin(header_length)[2:]).zfill(4)+(bin(reserved)[2:]).zfill(6)+(control_flag),2)
   #logger.debug("Header_control="+str((hed_res_ctrl))) #Value should be 20482
   tcp_header=struct.pack(">HHLLHHHH",src_port,dest_port,sqn,ack,hed_res_ctrl,window_size,checksum,urgent_ptr)
   tcp_checksum=make_tcp_checksum(src_ip,dest_ip,0,6,20,tcp_header)
   tcp_header=struct.pack(">HHLLHHHH",src_port,dest_port,sqn,ack,hed_res_ctrl,window_size,tcp_checksum,urgent_ptr)
   #logger.debug("tcp_header="+binascii.hexlify(tcp_header))
   logger.debug("Unpacked TCP Header="+str(struct.unpack(">HHLLHHHH",tcp_header)))
   return tcp_header
 


def make_tcp_checksum(src_ip,dest_ip,reserv,proto,leng,header):
   logger=logging.getLogger("Knocker.make_tcp_checksum")

   src_ip=socket.inet_aton(src_ip)
   dest_ip=socket.inet_aton(dest_ip)
   pseudo_head=struct.pack('>4s4sBBH',src_ip,dest_ip,reserv,proto,leng)
   pseudo_head=binascii.hexlify(pseudo_head+header)
   
   #pseudo_head='4500003c1c4640004006ac100a63ac100a0c'
   checksum=bin(0)[2:].zfill(16)
   for i in range(0,len(pseudo_head),4):

          
          str1=bin(int(pseudo_head[i:i+4], 16))[2:].zfill(16)
          
          checksum=bin(int(str1,2)+int(checksum,2))
          
          checksum=checksum[2:].zfill(16)
          if(len(checksum)>16):
            if(checksum[0]=='1'):
               checksum=bin(int(checksum[1:],2)+int(checksum[0],2))
               
               checksum=checksum[2:].zfill(16)
               
            else :
               checksum=checksum[1:].zfill(16)


   checksum=~int(checksum,2)&0xffff
   logger.debug("Checksum="+str(checksum))
   return checksum





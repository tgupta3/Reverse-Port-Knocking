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

   	if "URL" in errmsg:
   		print "Missing URL"
   		return

   	error_check=True
   	print errmsg

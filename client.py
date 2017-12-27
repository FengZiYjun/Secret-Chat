import socket
import threading
import queue
import select
from gui import *
import time
from myprotocol import *
import pyaes

HOST = 'localhost'
PORT = 9876

class Client(threading.Thread):
	def __init__(self, host, port):
		# target is the callable object to be invoked by the run() method
		super().__init__(daemon=True, target=self.run)

		# get local machine name, also the server
		self.host = host
		self.port = port
		self.sock = None

		# used by GUI
		# write buffer: from cliet to server
		# CHANGE! store bytes
		self.queue = queue.Queue()
		self.target = ''

		# the name of the login user
		self.login_user = ''

		# used in I/O
		self.lock = threading.RLock()
		self.buffer_size = 2048

		self.dest_addr = str(self.host) + ':' + str(self.port)

		# a bytes-like object geneated by __make_password
		self.__password = None

		self.connected = self.connect_to_server()
		if self.connected:
			self.gui = GUI(self)
			self.start() 	 # start the Client thread
			self.gui.start() # start the GUI thread


	def __validate_host(self, hostname):
		return type(hostname) is str and len(hostname) != 0

	def __make_password(self):
		import random
		import string
		# generate random 32-bytes password
		password = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(32))
		return password.encode()

	def __validate_paten(self, public, modulus):
		# to do
		return True

	def __encrypt(self, meg, public_key, n):
		return ' '.join([str((ord(ch) ** public_key) % n) for ch in meg])

	def str2int(self, *strs):
		return tuple([int(x) for x in strs])


	def connect_to_server(self):
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.connect((self.host, self.port))
		except ConnectionRefusedError:
			print('Inactive server, fail to connect.')
			return False

		# after connected, start RSA encryption
		# first requst toward server with user name
		self.sock.sendall(make_protocol_msg(self.login_user, self.dest_addr, 0, self.host, self.port).encode())
		
		# reveive a public paten
		rev_dict = analyze_protocol_msg(self.sock.recv(2048).decode('utf-8'))
		print(rev_dict)

		if rev_dict['affair'] != '1':
			print('server not response affair 1')
			return False

		public, modulus = tuple(rev_dict['msg'].split(' '))
		public, modulus = self.str2int(public, modulus)

		if self.__validate_paten(public, modulus):
			# generate a client password
			self.__password = self.__make_password()
			raw_msg = make_protocol_msg(self.__password.decode(), self.dest_addr, 1, self.host, self.port)
			# encrypt the password using public paten
			encr_msg = self.__encrypt(raw_msg, public, modulus)
			# send the encrpted password to server
			self.sock.sendall(encr_msg.encode())
		else:
			print('invalid paten')
			return False
		
		# receive server OK
		decr_bytes = pyaes.AESModeOfOperationCTR(self.__password).decrypt(self.sock.recv(2048))
		rec_dict = analyze_protocol_msg(decr_bytes.decode())
		print(rec_dict)
		if rec_dict['affair'] != '2':
			print('Server does not response 2')
			return False

		return True
	
	def encapsulate(self, msg, action=None):
		""" Make protocol and encrypt """
		# msg --- raw string
		# return: bytes-like message to send
		protocol = make_protocol_msg(msg, self.target, 2, self.host, self.port, action=action)
		encr_msg = pyaes.AESModeOfOperationCTR(self.__password).encrypt(protocol)
		return encr_msg

	def clear_queue(self):
		""" Clear queue by sending all messages"""
		while not self.queue.empty():
			data = self.queue.get()
			self.send(data)

	# called by GUI
	def notify_server(self, data, action):
    	# data --- raw string, the data of the action<login/logout>
		print('client notifies server:', data, action)
		#self.queue.put(data)
		act = None
		if action == "logout":
			act = '3'
		elif action == "login":
    		# when user logging in, GUI notifies server with the user input(uesrname)
			self.login_user = data
			act = '0'
		en_data = self.encapsulate(data, action=act)
		self.queue.put(en_data)

		if action == 'logout':
			self.clear_queue()
			self.sock.close()

	# call after receiving data
	def process_recv_msg(self, data):
		decr_bytes = pyaes.AESModeOfOperationCTR(self.__password).decrypt(data)
		rec_dict = analyze_protocol_msg(decr_bytes.decode())
		print('Client receives: ' + str(rec_dict))
		# notify other users a new incoming user
		if 'action' in rec_dict and rec_dict['action'] == '2':
			clients = rec_dict['msg'] + ' ALL' # ALL users for broadcast
			print('update client list: ' + clients)
			self.gui.main_window.update_login_list(clients.split(' '))
		else:
			# display message in the chat window
			message = rec_dict['msg']
			sender = rec_dict.get('action', '1 unknown')[2:]
			time_tag = time.asctime(time.localtime(time.time()))
			message = sender + ">>>" + message
			message = message + ' '*(60 - len(message)) + time_tag
			if len(message) > 0 and message[-1] != '\n':
				message += '\n'
			self.gui.display_message(message)

	def send(self, meg):
		# meg --- encrypted bytes
		with self.lock:
			try:
				self.sock.sendall(meg)
			except socket.error:
				self.sock.close()
				GUI.display_alert('client failed to send. Exit.')

	def close(self):
		self.sock.close()

	def run(self):
		inputs = [self.sock]
		outputs = [self.sock]
		while inputs:
			try:
				# three lists containing communication channels to monitor
				# a list of objects to be checked for incoming data to be read
				# a list of objects to receive outgoing data when there is room in buffer
				# a list of those that may have errors, often mixed of the input and output
				#  returns three new lists, containing subsets of the contents of the lists passed in
				readable, writable, exceptional = select.select(inputs, outputs, inputs)
			except ValueError:
				print('Server error')
				GUI.display_alert('Server error. Exit.')
				self.sock.close()
				break

			if self.sock in readable:
				with self.lock:
					try:
						data = self.sock.recv(self.buffer_size)
					except socket.error:
						print('Socket error in reading')
						GUI.display_alert('Socket error. Exit.')
						self.sock.close()
						break
				if len(data) is not 0:
					self.process_recv_msg(data)
				else:
					print('Server error')
					GUI.display_alert('Server error. Exit.')
					self.sock.close()
					break

			if self.sock in writable:
				try:
					if not self.queue.empty():
						# Remove and return an item from the queue.
						data = self.queue.get()
						self.send(data)
						# Indicate that a formerly enqueued task is complete. Used by queue consumer threads. 
						self.queue.task_done()
					else:
						# Suspend execution of the calling thread for the given number of seconds. 
						time.sleep(0.1)
				except socket.error:
					print('Socket error in reading')
					GUI.display_alert('Socket error. Exit.')
					self.sock.close()
					break

			if self.sock in exceptional:
				print('Server error')
				GUI.display_alert('Server error. Exit.')
				self.sock.close()
				break


# Create new client with (IP, port)
if __name__ == '__main__':
	Client(HOST, PORT)

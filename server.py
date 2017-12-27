import socket
from myprotocol import *
import threading
import queue
import time
import select
import pyaes

HOST = 'localhost'
PORT = 9876

class Server(threading.Thread):
	def __init__(self, host, port):
		super().__init__(daemon=True, target=self.run)
		
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		# get local machine name
		self.host = host
		self.port = port

		self.buffer_size = 2048

		# used as write buffer
		# key: client_socket  value: queue of encrypted bytes
		# sent by client_sock.send()
		self.msg_queues = {}

		# record all connection sockets
		self.connection_list = []

		# key: login_user(the name string)
		# value: client_socket
		self.login_dict = {}

		# key: client_socket
		# value: client password string
		self.__password_dict = {}

		# A reentrant lock must be released by the thread that acquired it. 
		# Once a thread has acquired a reentrant lock, the same thread may acquire it again without blocking; 
		# the thread must release it once for each time it has acquired it.
		self.lock = threading.RLock()

		# Socket setup
		self.shutdown = False
		try:
			# bind to the port with this server
			self.server_socket.bind((str(self.host), int(self.port)))
			# queue up to 5 requests
			self.server_socket.listen(10)
			
			#self.server_socket.setblocking(False)
			
			# start the server thread
			self.start()
		except socket.error:
			self.shutdown = True

		# main loop
		while not self.shutdown:
			# waiting for cmd
			msg = input()
			if msg == 'quit':
				for sock in self.connection_list:
					sock.close()
				self.shutdown = True
				self.server_socket.close()

	def remove_user(self, user, user_sock):
		if user in self.login_dict:
			del self.login_dict[user]
		if user_sock in self.connection_list:
			self.connection_list.remove(user_sock)
		if user_sock in self.msg_queues:
			del self.msg_queues[user_sock]
		if user_sock in self.__password_dict:
			del self.__password_dict[user_sock]

	def get_password(self, client_socket):
		if client_socket not in self.__password_dict:
			return None
		else:
			return self.__password_dict[client_socket]

	def set_password(self, client_sock, password):
		if client_sock not in self.__password_dict:
			self.__password_dict[client_sock] = password
		else:
			print('cannot reset password!')

	def run(self):
		print('server is running.')
		while True:
			with self.lock:
				try:
					# passively accept TCP client connection, waiting until connection arrives.
					client_sock, addr = self.server_socket.accept()
				except socket.error:
					time.sleep(1)
					continue

			print("Got a connection from %s" % str(addr))
			print('Socket connects %s and %s' % client_sock.getsockname(), client_sock.getpeername())

			#client_sock.setblocking(False)
			if client_sock not in self.connection_list:
				self.connection_list.append(client_sock)

			self.msg_queues[client_sock] = queue.Queue()
			ClientThread(self, client_sock, addr)


class ClientThread(threading.Thread):

	def __init__(self, master, sock, address):
		# master --- Server_socket
		# sock --- client_socket (connection socket)
		# address --- client addr
		super().__init__(daemon=True, target=self.run)

		self.master = master
		self.sock = sock
		self.address = address
		self.buffer_size = 2048

		# the user name
		self.login_user = ''
		self.inputs = []
		self.outpus = []

		# a string received from client
		self.__password = None

		self.start()

	def run(self):
		""" Main method for client thread processing client socket"""
		print('New thread started for connection from ' + str(self.address))
		self.inputs = [self.sock]
		self.outpus = [self.sock]
		while self.inputs:
			try:
				readable, writable, exceptional = select.select(self.inputs, self.outpus, self.inputs)
			except select.error:
				self.disconnect()
				break

			if self.sock in readable:
				try:
					data = self.sock.recv(self.buffer_size)
				except socket.error:
					self.disconnect()
					break

				shutdown = self.process_recv_data(data)
				# disconnect when empty data or logout
				if shutdown:
					self.disconnect()
					break

			if self.sock in writable:
				if not self.master.msg_queues[self.sock].empty():
					data = self.master.msg_queues[self.sock].get()
					try:
						# sent by socket directly
						self.sock.send(data)
					except socket.error:
						self.disconnect()
						break

			if self.sock in exceptional:
				self.disconnect()

		# out of the main loop
		print('Closing {} thread, connection'.format(self.login_user))

	def __broadcast(self, msg):
		for client_sock, queue in self.master.msg_queues.items():
			pswd = self.master.get_password(client_sock)
			if pswd is not None:
				cipher_bytes = pyaes.AESModeOfOperationCTR(pswd.encode()).encrypt(msg)
				queue.put(cipher_bytes)
			else:
				print('No such a client.')

	def update_client_list(self):
    	# Tell all users that client list has changed
		print('update_client_list')
		# used by GUI
		clients = ' '.join([user for user in self.master.login_dict])
		msg = make_protocol_msg(clients, 'ALL', '2', HOST, PORT, action='2')
		self.__broadcast(msg)

	def disconnect(self):
		"""disconnect from server"""
		print('Client {} has disconnected.'.format(self.login_user))
		# remove related info in Server
		self.master.remove_user(self.login_user, self.sock)
		self.sock.close()
		self.update_client_list()

	def process_recv_data(self, data):
		# return a shutdown signal
		if data is None or data == '':
			return True
		# data --- unicode bytes for the first time, but encrypted bytes later
		shutdown = False
		try:
			data = data.decode('utf-8')
		except UnicodeDecodeError:
			data = pyaes.AESModeOfOperationCTR(self.__password.encode()).decrypt(data).decode('utf-8')

		rec_dict = analyze_protocol_msg(data)
		print('Server receives: %s' % str(rec_dict))
		
		# check for first connection
		if rec_dict['affair'] == '0':

			# send the paten to client
			public, private, modulus = self.__make_keys()
			mes = make_protocol_msg(str(public) + ' ' + str(modulus), rec_dict['src'], '1', HOST, PORT)
			self.sock.sendall(mes.encode())

			# receive client password
			meg = self.__decrypt(self.sock.recv(1024).decode('utf-8'), private, modulus)
			rec_dict = analyze_protocol_msg(meg)
			print('receive: %s' % str(rec_dict))
			self.__password = rec_dict['msg']

			print('ready for login')
			# reply to the client of successful loggin
			msg = make_protocol_msg('ready for login', rec_dict['src'], '2', HOST, PORT, action='0')
			cipher_bytes = pyaes.AESModeOfOperationCTR(self.__password.encode()).encrypt(msg)
			self.sock.sendall(cipher_bytes)

		# Normal Communication
		elif rec_dict['affair'] == '2' and self.__password is not None:
			# action field available
			if 'action' in rec_dict:
				action = rec_dict['action']
				
				# user login
				if action == '0':
					# get the name of the login user
					self.login_user = rec_dict['msg']
			
					# allocate this socket to this user
					if self.login_user in self.master.login_dict:
						print('redundent login. Switch to new.')
						self.master.remove_user(self.login_user, self.master.login_dict[self.login_user])
					self.master.login_dict[self.login_user] = self.sock
					self.master.set_password(self.sock, self.__password)

					# tell all users the login of a new one
					self.update_client_list()

				# user log out
				elif action == '3':
					shutdown = True
				
				# one-to-one chat
				elif action[0] == '1':
					to_user = action[2:]
					from_user = self.login_user
					if to_user in self.master.login_dict:
						# get the connection socket of the target client
						sock = self.master.login_dict[to_user]
						msg = rec_dict['msg']
						print('message from ' + from_user + ' sent to ' + to_user + ': ' + msg)
						msg = make_protocol_msg(msg, to_user, 2, self.address[0], self.address[1], action='1 ' + from_user)
						pswd = self.master.get_password(sock)
						if pswd is not None:
							cipher_bytes = pyaes.AESModeOfOperationCTR(pswd.encode()).encrypt(msg)
							self.master.msg_queues[sock].put(cipher_bytes)
						else:
							print('cannot find pswd of user ' + to_user)
				
				# broadcast
				elif action[0] == '2':
					msg = rec_dict['msg']
					print('message broadcase: ' + msg)
					# action='2' has preserved for updating list, use action='1' instead
					msg = make_protocol_msg(msg, 'ALL', 2, self.address[0], self.address[1], action='1 ' + self.login_user)
					self.__broadcast(msg)

			else:
				print('no action available')
		return shutdown

	def extended_euclidean(self, a, b):
		# xa + yb = gcd(a, b)
		x,y, u,v = 0,1, 1,0
		while a != 0:
			q, r = b//a, b%a
			m, n = x-u*q, y-v*q
			b,a, x,y, u,v = a,r, u,v, m,n
		gcd = b
		return gcd, x, y

	def __make_keys(self):
		prime_P = 11
		prime_Q = 13
		n = prime_P * prime_Q
		phi = (prime_P - 1) * (prime_Q - 1)
		public_key = 7
		gcd, private_key, _ = self.extended_euclidean(public_key, phi)
		private_key += phi
		return public_key, private_key, n

	def __encrypt(self, meg, public_key, n):
		return ' '.join([str((ord(ch) ** public_key) % n) for ch in meg])

	def __decrypt(self, data, private_key, n):
		return ''.join([chr((int(x) ** private_key) % n) for x in data.split(' ')])



# Create new server with (IP, port)
if __name__ == '__main__':
    server = Server(HOST, PORT)
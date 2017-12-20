import socket

HOST = 'localhost'
PORT = 9876

class server:
	def __init__(self, sock=None):
		if sock is None:
			self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		else:
			self.server_socket = sock 

		# get local machine name
		self.host = HOST
		self.port = PORT
		# bind to the port with this server
		self.server_socket.bind((self.host, self.port))
		# queue up to 5 requests
		self.server_socket.listen(5)
		# record the listening IP
		self.client_pool = list()

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

	def __make_protocol_msg(self, message, dest_addr, affair):
		head = 'des ' + dest_addr + '\n'
		head += 'src ' + str(self.host) + ':' + str(self.port) + '\n'
		head += 'agent server.py' + '\n'
		head += str(affair) + '\n'
		head += 'head_length ' + str(len(head)) + '\n'
		return (head + str(message)).encode()

	def __analyze_protocol_msg(self, data):
		ret = dict()
		labels = ['des', 'src', 'agent', 'affair', 'head_length', 'msg']
		pt = 0
		for label in labels[:-1]:
			pt = data.find('\n')
			ret[label] = data[0: pt]
			data = data[pt+1:]
		ret[labels[-1]] = data
		return ret

	def run(self):

		while True:
			# establish a connection
			# passively accept TCP client connection, waiting until connection arrives.
			clientsocket,addr = self.server_socket.accept()

			print("Got a connection from %s" % str(addr))
			print('Socket connects %s and %s' % clientsocket.getsockname(), clientsocket.getpeername())

			meg = clientsocket.recv(1024)
			rec_dict = self.__analyze_protocol_msg(meg.decode('utf-8'))
			print('receive: %s' % str(rec_dict))

			# check for first connection
			if str(addr) not in self.client_pool and rec_dict['affair'] == '0':
				self.client_pool.append(str(addr))
				public, private, modulus = self.__make_keys()
				mes = self.__make_protocol_msg(str(public) + ' ' + str(modulus), rec_dict['des'], '1')
				clientsocket.send(mes)

				meg = self.__decrypt(clientsocket.recv(1024).decode('utf-8'), private, modulus)
				rec_dict = self.__analyze_protocol_msg(meg)
				print('receive: %s' % str(rec_dict))
				clientsocket.close()
				print('socket closed')
			else:
			
				#clientsocket.send(send_meg.encode('utf-8'))
				clientsocket.close() 
			



server = server()
server.run()



'''
# create a socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# get local machine name
host = socket.gethostname()                           
port = 9999                                           

# bind to the port with this server
server.bind((host, port))                                  

# queue up to 5 requests
server.listen(5)                                           
'''


import socket

class Client:
	def __init__(self, sock=None):
		if sock is None:
			self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		else:
			self.client_socket = sock

		# get local machine name, also the server
		self.host = socket.gethostname()
		self.port = 9876
		self.dest_addr = str(self.host) + ':' + str(self.port)

	def __validate_host(self, hostname):
		return type(hostname) is str and len(hostname) != 0

	def __make_protocol_msg(self, message, dest_addr, affair):
		head = 'des ' + dest_addr + '\n'
		head += 'src ' + str(self.host) + ':' + str(self.port) + '\n'
		head += 'agent client.py' + '\n'
		head +=  str(affair) + '\n'
		head += 'head_length ' + str(len(head)) + '\n'
		return (head + str(message))

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


	def __make_password(self):
		# generate random password
		from numpy.random import rand
		return int(rand(1) * (10**8))

	def __validate_paten(self, public, modulus):
		# do nothing
		return True

	def __encrypt(self, meg, public_key, n):
		return ' '.join([str((ord(ch) ** public_key) % n) for ch in meg])

	def str2int(self, *strs):
		return tuple([int(x) for x in strs])

	def connect(self):
		if self.port > 999 and self.__validate_host(self.host):
			self.client_socket.connect((self.host, self.port))
			self.client_socket.sendall(self.__make_protocol_msg('', self.dest_addr, 0).encode())

			rev_dict = self.__analyze_protocol_msg(self.receive())
			print(rev_dict)
			if rev_dict['affair'] == '1':
				public, modulus = tuple(rev_dict['msg'].split(' '))
				public, modulus = self.str2int(public, modulus)
				if self.__validate_paten(public, modulus):
					raw_msg = self.__make_protocol_msg(self.__make_password(), self.dest_addr, 1)
					encr_msg = self.__encrypt(raw_msg, public, modulus)
					self.client_socket.sendall(encr_msg.encode())

		else:
			raise('invalid parameters for connect.')

	def send(self, meg):
		self.client_socket.sendall(self.__make_protocol_msg(meg, self.dest_addr, 2))

	def receive(self):
		return self.client_socket.recv(2048).decode('utf-8')

	def close(self):
		self.client_socket.close()





client = Client()
client.connect()
#client.send('hey,buddy')
#print(client.receive())
client.close()


'''
# create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

# get local machine name
host = socket.gethostname()                           
port = 9876

# connection to the server with hostname on the port.
s.connect((host, port))                               

# Receive no more than 1024 bytes
#msg = s.recv(2048)                                     
#print (msg.decode('utf-8'))

s.sendall(make_protocol_message('hello', host, port))
msg = s.recv(2048)                                     
print (msg.decode('utf-8'))

s.close()
'''
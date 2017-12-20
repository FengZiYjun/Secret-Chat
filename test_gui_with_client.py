import threading
import queue
import socket
import select
from gui import *
import time

HOST = 'localhost'
PORT = 9876

class Client(threading.Thread):
	def __init__(self, host, port):
		# target is the callable object to be invoked by the run() method
		super().__init__(daemon=True, target=self.run)

		self.host = host
		self.port = port
		self.sock = None

		# used by GUI
		self.queue = queue.Queue() # write buffer
		self.target = ''

		# used in I/O
		self.lock = threading.RLock()
		self.buffer_size = 2048

		self.connected = self.connect_to_server()
		if self.connected:
			self.gui = GUI(self)
			self.start() 	 # start the Client thread
			self.gui.start() # start the GUI thread


	def connect_to_server(self):
		try:
			self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.sock.connect((self.host, self.port))
		except ConnectionRefusedError:
			print('Inactive server, fail to connect.')
			return False
		return True

	# used by GUI
	def notify_server(self, data, action):
		print(data, action)

	def process_inputs(self, data):
		print('process inputs')

	def send(self, msg):
		print('send message')

	def run(self):
		inputs = [self.sock]
		outputs = [self.sock]
		while inputs:
			try:
				# three lists containing communication channels to monitor
				# a list of objects to be checked for incoming data to be read
				# a list of objects to receive outgoing data then there is room in buffer
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
						self.close()
						break

				self.process_inputs(data)

			if self.sock in writable:
				if not self.queue.empty():
					# Remove and return an item from the queue.
					data = self.queue.get()
					self.send(data)
					# Indicate that a formerly enqueued task is complete. Used by queue consumer threads. 
					self.queue.task_done()
				else:
					# Suspend execution of the calling thread for the given number of seconds. 
					time.sleep(0.1)

			if self.sock in exceptional:
				print('Server error')
				GUI.display_alert('Server error. Exit.')
				self.sock.close()
				break


# Create new client with (IP, port)
if __name__ == '__main__':
	Client(HOST, PORT)
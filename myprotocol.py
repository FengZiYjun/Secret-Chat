# -*- coding: utf-8 -*-


''' 
	des <hostname>:<port>
	src <hostname>:<port>
	user-agent <xxx.py>
	affair 0/1/2
	head_length <number>
	action: login(0)/chatToOne(1 + username)/broadcast(2)/logout(3)  client ---> server
		server--->client action 2 is preserverd for updating user list.
	msg
'''

"""
	affair: 
	0 means client start requesting. 
	1 means server first acknowledges and client acknowledges.
	2 means normal communication. This means action field is available.
"""

def make_protocol_msg(message, dest_addr, affair, host, port, action=None):
	# input: parameters
	# return: string, the message
	head =  dest_addr + '\r\n'
	head += str(host) + ':' + str(port) + '\r\n'
	head += 'server.py' + '\r\n'
	head += str(affair) + '\r\n'
	head += str(len(head)) + '\r\n'
	if action is not None:
		head +=  action + '\r\n'

	protocol = head + message
	return protocol


def analyze_protocol_msg(data):
	# inupt: data --- string
	# return: dictionary
	ret = dict()
	labels = ['des', 'src', 'agent', 'affair', 'head_length', 'msg']
	pt = 0
	for label in labels[:-1]:
		pt = data.find('\r\n') # pt points at '\r'
		if pt != -1:
			ret[label] = data[0: pt]
			if len(data[pt+1:]) > 1:
				data = data[pt+2:]
			else:
				data = ''
		else:
			print(label + ' not found!')

	# check for action
	pt = data.find('\r\n')
	if pt != -1:
		ret['action'] = data[0:pt]
		if len(data[pt+1:]) > 1:
			data = data[pt+2:]
		else:
			data = ''
	ret[labels[-1]] = data
	return ret

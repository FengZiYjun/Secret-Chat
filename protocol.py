# this file defines the protocol

'''
	des <hostname>:<port>
	src <hostname>:<port>
	user-agent <xxx.py>
	affair 0/1/2
	head_length <number>
'''

def make_protocol_msg(dest_addr, src_addr, agent, message):
	head =  dest_addr + '\n'
	head += src_addr + '\n'
	head += 'agent client.py' + '\n'
	return (head + message).encode()



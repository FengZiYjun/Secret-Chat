
def extended_euclidean(a, b):
	# xa + yb = gcd(a, b)
	x,y, u,v = 0,1, 1,0
	while a != 0:
		q, r = b//a, b%a
		m, n = x-u*q, y-v*q
		b,a, x,y, u,v = a,r, u,v, m,n
	gcd = b
	return gcd, x, y

def make_keys():
	prime_P = 11
	prime_Q = 13
	n = prime_P * prime_Q
	phi = (prime_P - 1) * (prime_Q - 1)
	public_key = 7
	gcd, private_key, _ = extended_euclidean(public_key, phi)
	private_key += phi
	return public_key, private_key, n

def encrypt(meg, public_key, n):
	return ' '.join([str((ord(ch) ** public_key) % n) for ch in meg])

def decrypt(data, private_key, n):
	return ''.join([chr((int(x) ** private_key) % n) for x in data.split(' ')])


public, private, n = make_keys()
print((public, private, n))
encr = encrypt("this is a message", public, n)
print(encr)
decr =  decrypt(encr, private, n)
print(decr)
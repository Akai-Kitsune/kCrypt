# Copyright (C) 09.09.2021 Aleksei Likhachev 
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the KI General Public License version for more details.
#Version 1.1.0
#--------------------------------------------------------------------------------------------------
import rsa
import sys
import random
import string
import re
import time
#--------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
class Stack(object):
	def __init__(self):
		self.items = []
		self.__length = 0

	def push_back(self, value):
		self.items.append(value)
		self.__length += 1

	def pop_back(self):
		self.items.pop 
		self.__length -= 1

	def empty(self):
		return True if self.__length == 0 else False

	def getLength(self):
		return self.__length
#--------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
class Config:
	def __init__(self, name):
		try:
			with open(name, 'r') as cfg:
				tmp = cfg.read()
				cfg.close()
				stack = ''
				stackData = ''
				self.parsed = {}
				i = 0
				n = len(tmp)
				for i in range(0, n):
					while i < n and tmp[i] != '{':
						stack += tmp[i]
						i+=1
					i += 1
					while i < n and tmp[i] != '}':
						stackData += tmp[i]
						i += 1
					self.parsed[stack] = stackData
					stack = ''
					stackData = ''
		except:
			log.write(tolog('ERROR with open cfg file', 'error __init__'))

	def getKeys(self):
		#
		keyPublic = None
		keyPrivate = None
		if 'keyPublic' in self.parsed:
				keyPublic = rsa.PublicKey.load_pkcs1(self.parsed['keyPublic'], 'PEM')
		if 'keyPrivate' in self.parsed:
				keyPrivate =  rsa.PrivateKey.load_pkcs1(self.parsed['keyPrivate'], 'PEM')
		return (keyPublic, keyPrivate)

	def getKeyByName(self, name):
		if name in self.parsed:
			return rsa.PublicKey.load_pkcs1(self.parsed[name], 'PEM')
		else:
			return None

	def getValueByName(self, name):
		if name in self.parsed:
			return self.parsed[name]
		else:
			return None

	def addKeyToConfig(self, name, nameFilePem):
		try:
			with open('cfg.cfg', 'ab') as cfg:
				with open(nameFilePem, 'rb') as filePem:
					key = rsa.PublicKey.load_pkcs1(filePem.read(), 'PEM')
					cfg.write(bytes(name, 'utf-8') + b'{'+ key.save_pkcs1('PEM')+ b'}')
					filePem.close()
		except:
			log.write(tolog('ERROR with open cfg or PEM file', 'error addKeyToConfig'))

	def addValueToConfig(self, name, value):
		try:
			self.cfg.write(name + '{' + value + '}')
		except:
			log.write(tolog('ERROR with open cfg file', 'error addValueToConfig'))

#--------------------------------------------------------------------------------------------------
def buildName(size):    
	return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(size))

def tolog(nameOperation, str):
	return ('\n----------\n' + nameOperation + '\n----------\n' + '[' + str +']')

#--------------------------------------------------------------------------------------------------
#stackOperation = []
#Config
#--------------------------------------------------------------------------------------------------
keyDefoltSizeRsa = 1024
keyDefoltSizeEcdsa = 1024
size = len(sys.argv)

fcfg = False, 0
fgenerate = False, 0
fencrypt = False, 0
fdecrypt = False, 0
fsign = False, 0
fvsign = False, 0
ffile = False, 0
ferror = 0
faddkey = False, 0
message = ''
id = ''
#--------------------------------------------------------------------------------------------------

#--------------------------------------------------------------------------------------------------
log = open('klog.log', 'w')
log.write(tolog('##START##', '#####'))
#log.write('\n----------time start----------\n' +'['+']' + '\n')
# cfg = Config('cfg.cfg')
if size == 1:
	try:
		with open('readme.txt', 'r') as readme:
			print(readme.read())
			readme.close()
	except Exception:
		print('error open file readme.txt')
else:
	stack = Stack()
	# Parcing argv value
	for i in range(0, size):
		# We need load cfg
		if sys.argv[i] == '-cfg':
			fcfg = True, i
		# Flag for generation rsa keys
		elif sys.argv[i] == '-g':
			fgenerate = (True, i+1)
		# Flag for encrypt message
		elif sys.argv[i] == '-ue':
			fencrypt = (True, i+1)
		# Flag for decrypt message
		elif sys.argv[i] == '-ud':
			fdecrypt = (True, i+1)
		# Flag for sign file
		elif sys.argv[i] == '-sign':
			fsign = (True, i+1)
		# Flag for verification sign 
		elif sys.argv[i] == '-vsign':
			fvsign = (True, i+1)
		# Load file by name
		elif sys.argv[i] == '-f':
			ffile = True, i+1
		elif sys.argv[i] == '-add':
			faddkey = True, i+1
		# Get id
		elif sys.argv[i] == '-id':
			try:
				id = sys.argv[i+1]
			except:
				id = ''

	# We need create config file with keys
	if fcfg[0] == True and fgenerate[0] == True:
		#try:
		if type(int(sys.argv[fgenerate[1]])) == type(int()):
			(keyPublic, keyPrivate) = rsa.newkeys(int(sys.argv[fgenerate[1]]))	
			with open('cfg.cfg', 'wb') as cfg:
				filePublic = open(buildName(7)  + '_public', 'wb')
				cfg.write(b'size{' + bytes(sys.argv[fgenerate[1]], 'utf-8') + b'}')
				cfg.write(b'keyPublic{' + keyPublic.save_pkcs1('PEM') + b'}')
				cfg.write(b'keyPrivate{' + keyPrivate.save_pkcs1('PEM') + b'}')
				filePublic.write((keyPublic.save_pkcs1('PEM')))
				# Close stream
				cfg.close()
				filePublic.close()
				# Write in log file
				log.write(tolog('Keys was created successfully', 'ok'))
		else:
			(keyPublic, keyPrivate) = rsa.newkeys(1024)	
			with open('cfg.cfg', 'wb') as cfg:
				filePublic = open(buildName(7)  + '_public', 'wb')
				cfg.addValueToConfig('size', '1024')
				cfg.write(b'keyPublic{' + keyPublic.save_pkcs1('PEM') + b'}')
				cfg.write(b'keyPrivate{' + keyPrivate.save_pkcs1('PEM') + b'}')
				filePublic.write((keyPublic.save_pkcs1('PEM')))
				# Close stream
				cfg.close()
				filePublic.close()
				# Write in log file
				log.write(tolog('Keys was created successfully', ''))
		#except:
			#log.write(tolog('ERROR generate keys', 'error'))

	#It's mean that cfg was created, we just need load keys
	elif fcfg[0] == True and fgenerate == False:
		try:
			cfg = Config('cfg.cfg')
			(keyPublic, keyPrivate) = cfg.getKeys()
		except:
			log.write(tolog('ERROR open cfg file', ''))
			exit(-1)
	# Add key to config
	if faddkey[0] == True:
		try:
			cfg = Config('cfg.cfg')
			cfg.addKeyToConfig('interKey'+id, sys.argv[faddkey[1]])
			log.write(tolog('Successfully add key to cfg file', 'ok'))
		except:
			log.write(tolog('ERROR open key PEM file', 'not found ' + sys.argv[faddkey[1]]))
			exit(-1)
	#Load message file
	if ffile[0] == True:
		try:
			with open(sys.argv[ffile[1]], 'rb') as file:
				message = file.read()
				file.close()
				log.write(tolog('Open file', sys.argv[ffile[1]]))
				log.write(tolog('Successfully open file', 'ok'))
		except:
			log.write(tolog('ERROR open message file', 'error'))
			exit(-1)
	else:
		# log.write('----------Error open message file, please use -f messageName----------\n')
		# print('----------Error open message file, please use -f messageName----------\n')
		next
	#We need encrypt message
	if fencrypt[0] == True:
		if fcfg[0] == False:
			pem = open(sys.argv[fencrypt[1]], 'rb')
			interKey = rsa.PublicKey.load_pkcs1(pem.read(), 'PEM')
			pem.close()
		else: 
			cfg = Config('cfg.cfg')
			interKey = cfg.getKeyByName('interKey'+id)
		stack = b''
		i = 0; j = 64
		while i <= len(message):
			stack += rsa.encrypt(message[i:j], interKey)
			i += 64; j += 64
		encMessage = open(buildName(7) + '_em.txt', 'wb')
		encMessage.write(stack)
		encMessage.close()
		del interKey, stack
		log.write('----------Encrypt file----------\n')

	elif fdecrypt[0] == True:
		cfg = Config('cfg.cfg')
		(keyPublic, keyPrivate) = cfg.getKeys()
		keySize = int(cfg.getValueByName('size')) // 8 
		stack = b''
		i = 0; j = keySize
		while j <= len(message):
			stack += rsa.decrypt(message[i:j], keyPrivate)
			i += keySize; j += keySize
		decMessage = open(buildName(7) + '_dm.txt', 'wb')
		decMessage.write(stack)
		decMessage.close()
		del keyPublic
		if fvsign == False:
			del stack
		else:
			message = stack
		log.write(tolog('decrypt file', 'ok'))

	# We make sign file with our private key
	if fsign[0] == True:
		cfg = Config('cfg.cfg')
		(keyPublic, keyPrivate) = cfg.getKeys()
		sign = open(buildName(7) + '_sign', 'wb')
		sign.write(rsa.sign(message, keyPrivate, 'SHA-512'))
		sign.close()

	# Decrypt message
	if fvsign[0] == True:
		try:
			cfg = Config('cfg.cfg')
			(keyPublic, keyPrivate) = cfg.getKeys()
			sign = open(sys.argv[fvsign[1]], 'rb')
			keyPublic = cfg.getKeyByName('interKey'+id)
			rsa.verify(message, sign.read(), keyPublic)
			sign.close()
			print('\n-------The signature corresponds to the addressee-------\n')
			log.write('\n-------The signature corresponds to the addressee-------\n')
		except:
			print('\nERROR\n-------THE SIGNATURE DOES NOT CORRESPONDS TO THE ADDRESSEE-------\n')
			log.write('\nERROR\n-------THE SIGNATURE DOES NOT CORRESPONDS TO THE ADDRESSEE-------\n')
	log.close()
#--------------------------------------------------------------------------------------------------
import zlib
import binascii
import random
import string
import re


DecodeString = '\x65hhhhFuckSpyTechUsersWeDaMilitiaAnonym00se'

def Decode(s):
    global DecodeString
    return ''.join([chr(ord(c) ^ ord(DecodeString[i % len(DecodeString)])) for i, c in enumerate(s)])
    
def switchToHex(s):
	s = s.split('\\x')
	s = s[1:]
	finalString = ""
	for i in s:
		finalString += chr(int(i, 16))
	return finalString
	
def fixExp(matchobj):
	return Decode(zlib.decompress(switchToHex(matchobj.group(0)[28:-3])))
		
def main():

	file1 = open('Necro.py', 'r+')
	allNecro = file1.readlines()
	allNecro = ''.join(allNecro)
	file1.close()
	
	
	allNecro = re.sub('SlHhRejXDa\(zlib.decompress\(("[^\)]+")\)\)', fixExp, allNecro)
	
	file2 = open('decodedNecro.py', 'w')
	file2.write(allNecro)
	file2.close()
	
	
	print(allNecro)

main()

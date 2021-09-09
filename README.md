Version 1.1.0
Data encryption software based on the RSA algorithm with an arbitrary key length

To use it, run the cmd with start_cmd.cmd

1) First of all, you should create a configuration file with the command
	crypt.py -cfg -g 1024 where 1024 - the length of the key in bits. 
	crypt.py -cfg -g  
	Values lower than this are not safe. For important documents use 2048 or 5096

2) To exchange messages, you must get the public key (marked _public) of the other party. Add it to the configuration
	file using 
	crypt.py -cfg -add key_name -id recipient identifier
	crypt.py -cfg -add -id 

3) To sign a document, use the command
	crypt.py -cfg -sign -f message name
	crypt.py -cfg -sign -f 

4) To encrypt a document use the command
	crypt.py -cfg -ue -id recipient id -f document name
	crypt.py -cfg -ue -id -f 
	If you want to encrypt a file without using a configuration file, use the command
	crypt.py -ue public key name -f document name

5) To decrypt a message, use the command
	crypt.py -cfg -ud -f message name
	crypt.py -cfg -ud -f  

6) To verify a document's signature, use 
	crypt.py -cfg -vsign signature file name -id recipient -f the name of the decrypted message
	crypt.py -cfg -vsign -id -f 


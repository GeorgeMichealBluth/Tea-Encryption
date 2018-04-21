# Tea-Encryption
Tea Server and Client

This code was written for the Crytography class at MSU as part of assignment 4.

The server generates an RSA key and sends it to the client.  Upon receiving the encrypted key and initial value from the client the server decrypts both and proceeds to receive TEA encrypted blocks of data from the client.  The server decrypts each block and builds a decrypted file.  

The client generates a key and initial value for the TEA encryption.  Upon receiving the RSA key from the server, the client will encrypt the key and iv and send them back to the server.  The client will TEA encrypt a file using CBC and send encrypted chunks to the server.  

This current edition is a rough upload with a disgusting amount of comments.  

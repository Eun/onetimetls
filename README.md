# onetimetls

A way to establish a secure tls connection without a certified root certificate.

## How does it work
Clients and Server share a password which is used later for decryption

 1. Client establishes a tcp connection to Server
 2. Server sends a one time certificate and a one time encrypted private key to the client  
    This certificate and key is only valid for this current connection.
 3. Client decrypts private key, and uses private key + certificate to authenticate with server (on the same connection)
 
If the client is not able to decrypt the key in a specific time the connection will be closed (by server).

## Security
An attacker can download the private key by establishing a connection to the server and bruteforcing the password.
If the attacker found the password, he can establish a new connection and use the found password for the new connection.  
Therefore it is recommended to change the password after some time.  
As an alternertive it might be useful to use a OTP in some form for the password.
 
 
### Notes
Tests are messy but working.
Use `go test -gcflags=-l  ./...` to test
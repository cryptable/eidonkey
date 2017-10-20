EIDONKEY
========

A Rust project to read out and use the Belgian eID card through a local SSL-WebServer. Using AJAX calls in your web application, you are able to read out or use the Belgian eId card.
This replaces the java applet. We'll try also that you don't need to use the Middleware.


REST-API
--------
The REST-API uses JSON as data-structure format for response data. All requests to the service uses GET
The base URL: https://localhost:10443

###Overvie of API-URLs:

| path | method | explanation |
| /version | GET | get the version of the API (O.1.0) |
| /identity | GET | gst the identity information of the person to whom the card belongs to |
| /address | GET | get the address information of the person to whom the card belongs to |
| /photo | GET | get the photo of the person |
| /signature/authentication | GET | get a signature of the hash given as a parameter for authentication |
| /signature/signing | GET | get a signature of the hash given as a parameter foe a digital signature |
| /certificates/authentication | GET | get the authentication certificatoion |
| /certificates/signing | GET | get the signing certificate |
| /certificates/rootca| GET | get the root ca certificate |
| /certificates/ca | GET | get the intermidiate CA to which the certficates |
| /certificates/rrn | GET | get the certificate of Rijkregister|

DESIGN
------

Notes
-----
This is highly experimental. 
The service must be protected by the OS and with a password.
You have to import the certificate into your OS or Firefox browser:
- Windows -> Certificate store
- Mac OS X -> Key chain
- Linux -> /etc/ssl, /local/etc/ssl or somewhere else in a protected directory

Create self-signed certificate
------------------------------
openssl req -x509 -sha256 -newkey rsa:2048 -keyout certificate.key -out certificate.crt -days 1024 -nodes -subj '/CN=localhost'
or
eidonkey --gencert
it will generate cert.crt and cert.key (unprotected private key) in the current directory, which can directly be used by the service.

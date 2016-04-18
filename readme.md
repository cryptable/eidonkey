EIDONKEY
========

A Rust project to read out and use the Belgian eID card through a local SSL-WebServer. Using AJAX calls in your web application, you are able to read out or use the Belgian eId card.
This replaces the java applet. We'll try also that you don't need to use the Middleware.

Notes
-----
This is highly experimental. 
The certificate and private key delivered in the project should be replace with your own certificate/private key.
The private key is not protected (it is plain). During setup it should be protected by the OS and with a password.
You have to import the certificate into your OS or Firefox browser:
- Windows -> Certificate store
- Mac OS X -> Key chain
- Linux -> /etc/ssl, /local/etc/ssl or somewhere else in a protected directory

Supported now:
https://localhost:8443/identity -> identity information without binary stuff (need a base64 encoder in Rust first)
https://localhost:8443/address -> address information without binary stuff (need a base64 encoder in Rust first)

Create self-signed certificate
------------------------------
openssl req -x509 -sha256 -newkey rsa:2048 -keyout certificate.key -out certificate.crt -days 1024 -nodes -subj '/CN=localhost'
or
eidonkey --gencert
it will generate cert.crt and cert.key (unprotected private key) in the current directory, which can directly be used by the service.

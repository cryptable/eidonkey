Create self-signed certificate
------------------------------
openssl req -x509 -sha256 -newkey rsa:2048 -keyout certificate.key -out certificate.crt -days 1024 -nodes -subj '/CN=localhost'

Information reading eId using pcsc
----------------------------------
http://wiki.yobi.be/wiki/Belgian_eID#opensc-tool
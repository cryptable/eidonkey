Installation on a Mac OS X
==========================

1) The eidonkey is protected by root account. So it needs to be installed as a root process under the directory /opt/eidonkey. It should contain the file under this (macosx) directory and the 2 build files: eidonkey, pincode. eidonkey is the server and the pincode is the application to ask for the pincode.

2) As a post installation you should run post-install-eidonkey (as a root user). This will protect the eidonkey, pincode, post-install-eidonkey, post-startup-eidonkey, org.cryptable.eidonkey.plist so that only the root user has read and execute access. The import-ca-firefox and the whole firefox directory, which will be used to import the cacertificate into the truststore, will be accessible by the user. The script will open the ports so the browser has access to the local service. The org.cryptable.eidonkey.plist will be installed in the /Library/LaunchDaemons/ to start the webservice as a daemon. The org.cryptable.import-ca-firefox.plist will be installed in the /Library/LaunchAgents/ directory, so it will import the CA certificate into the firefox browser, when the User logs in.
A symbolic link is created to /usr/local/bin for the import-ca-firefox script to import the CA certificate manually when a restart of the daemon was necessary.
- post-install-eidonkey is only used once to install the stuff above
- post-startup-eidonkey is started each time eidonkey is finished initializing the service (generating the SSL certificate with the CA). It installs the CA certificate into the MacOS X Truststore
- import-ca-firefox and firefox/ directory is used to import the CA certificate in the truststore of firefox (located ~/Library/Application\ Support/Firefox/Profiles/*)
- eidonkey is the service itself
- pincode is application which asks the pincode

Process and Security
====================
##Process
The most sensitive process is the signing and authentication process. Both are ver alike:
It all runs ounder root account!
https://localhost:10433/signature/signing?data=<HASH> -> eidonkey execute pincode -> pincode asks PIN -> pincode returns JSON with PIN in plain -> eidonkey request signature to the card

##Security issues
It is a POC (Proof Of Concept) and can be always improved.
1) 'root' access will be break the security of the service, because you can change everything of the service itself. It is protected using the OS permission features. But at the end 'root' access can break almost everyhting on today services.
2) The http service is written in Rust to protect the application against buffer overruns. The language gives a inherent protection against these kind of failures, which exist in C. The service is dependent on following C-librarie: openssl, pcsclite. It cannot protect against weaknesses of these libraries. 
3) The pincode is an C-application using wxWidgets, which can contain security problems. The main problem is that it shows the password in plain when you run it manually (as 'root', because only 'root' has access) to the stdout. The Service catches the stdout and use it to connect to the card. The pincode application is protected by 'root' and hash in the eidonkey.sig file. The security can be enhanced using a Pinpad reader.
4) TLS v1.1 is configured.

# sftpserver

SFTP Server (SSH File Transfer Protocol) based on `Apache MINA SSHD`. Open Source Java project under Apache License v2.0

---

## Config (sftpd.conf)
Config file must be in class-path, general format is:

	#
	## Global Options
	#
	# Listen on TCP port 22222
	sftpserver.global.port=22222
	# Disable compression (requires jzlib) (default: false)
	sftpserver.global.compress=false
	# Enable dummy shell (default: false)
	sftpserver.global.dummyshell=true
	#
	## Configure user "test"
	#
	# Password for user
	sftpserver.user.test.userpassword=clean-unencripted-password
	# Set user home directory (chrooted)
	sftpserver.user.test.homedirectory=/home/test/
	# Enable user (default: false)
	sftpserver.user.test.enableflag=true
	# Enable write (default: false)
	sftpserver.user.test.writepermission=true
	#

---

## Compile (handmade)

    LIB="lib/mina-core-XXX.jar:lib/sshd-core-XXX.jar:lib/slf4j-api-XXX.jar:slf4j-simple-XXX.jar:lib/bcprov-jdkXXX.jar"
    mkdir classes
    javac -d classes/ -cp "$LIB" src/net/sftp/Server.java
    jar cvf sftpserver-x.y.z.jar -C classes/ .

## Running

    java -cp .:sftpserver-x.y.z.jar net.sftp.Server

---

# TODOs

* Encrypted Passwords (SHA1/MD5)
* Publickey Authenticator
* Use Java SecurityManager/Policy File

# DONEs

* Non operating system accounts
* Homes are chrooted
* ReadOnly accounts

## MISC
Current harcoded values:

* Hostkeys are writed to: `hostkey.pem` or `hostkey.set` in current directory
* Only SHA1 (160bits) are enabled for HMAC (MD5, MD5-96, SHA1-96 are disabled)

---

Requirement (external JARs):

[Apache MINA SSHD](http://mina.apache.org/sshd-project/)

* mina-core-`XXX`.jar
* sshd-core-`XXX`.jar
* slf4j-api-`XXX`.jar
* slf4j-simple-`XXX`.jar
* bcprov-jdk`XXX`.jar

[JZlib (for compression)](http://www.jcraft.com/jzlib/)

* jzlib-`XXX`.jar

---
Inspired in [mina-sshd](http://svn.apache.org/viewvc/mina/sshd/tags/sshd-0.8.0/sshd-core/src/main/java/org/apache/sshd/SshServer.java?view=markup) and [openssh](http://www.openssh.org/).

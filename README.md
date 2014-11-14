# sftpserver

SFTP Server (SSH File Transfer Protocol) based on `Apache MINA SSHD`. Open Source Java project under Apache License v2.0

### Current Stable Version is [1.0.3](https://maven-release.s3.amazonaws.com/release/org/javastack/sftpserver/1.0.3/sftpserver-1.0.3-bin.zip)

---

## Config:

###### `${sftp.home}/conf/[id]/sftpd.properties`

	#
	## Global Options
	#
	# Listen on TCP port 22222
	sftpserver.global.port=22222
	# Enable compression (requires jzlib) (default: false)
	sftpserver.global.compress=true
	# Enable dummy shell (default: false)
	sftpserver.global.dummyshell=true
	#
	## Configure user "test"
	#
	# Password for user
	sftpserver.user.test.userpassword=clean-unencripted-password
	# Set user home directory (chrooted)
	sftpserver.user.test.homedirectory=./home/test/
	# Enable user (default: false)
	sftpserver.user.test.enableflag=true
	# Enable write (default: false)
	sftpserver.user.test.writepermission=true
	#

---

## Running (Linux)

    ./bin/sftpd.sh <start|stop|restart|status> [id]

---

# TODOs

* Encrypted Passwords (SHA1/MD5)
* Publickey Authenticator

# DONEs

* Use Java SecurityManager/Policy File
* Non operating system accounts
* Homes are chrooted
* ReadOnly accounts

## MISC
Current harcoded values:

* Hostkeys are writed to: `hostkey.pem` or `hostkey.set` in `${sftp.home}/keys/` directory
* SecurityManager/Policy File is in `lib/sftpd.policy`
* Only SHA1 (160bits) are enabled for HMAC (MD5, MD5-96, SHA1-96 are disabled)

---

Maven Dependencies:

[Apache MINA SSHD](http://mina.apache.org/sshd-project/)

* mina-core-`XXX`.jar
* sshd-core-`XXX`.jar

[Log4J (logging)](http://logging.apache.org/log4j/1.2/)

* log4j-`XXX`.jar

[SLF4J (logging)](http://www.slf4j.org/)

* slf4j-api-`XXX`.jar
* slf4j-log4j12-`XXX`.jar

[Bouncy Castle (encryption)](http://www.bouncycastle.org/java.html)

* bcprov-jdk`XXX`.jar

[JZlib (for compression)](http://www.jcraft.com/jzlib/)

* jzlib-`XXX`.jar

---
Inspired in [mina-sshd](http://svn.apache.org/viewvc/mina/sshd/tags/sshd-0.8.0/sshd-core/src/main/java/org/apache/sshd/SshServer.java?view=markup) and [openssh](http://www.openssh.org/).

package org.javastack.sftpserver;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.util.Arrays;

import org.apache.commons.codec.digest.Md5Crypt;
import org.apache.commons.codec.digest.Sha2Crypt;

public class PasswordEncrypt {
	private static final Charset US_ASCII = Charset.forName("US-ASCII");
	public final String md5;
	public final String apr1; // md5
	public final String sha256;
	public final String sha512;

	public PasswordEncrypt(final String key) {
		final byte[] keyBytes = key.getBytes(US_ASCII);
		this.md5 = Md5Crypt.md5Crypt(keyBytes.clone());
		this.apr1 = Md5Crypt.apr1Crypt(keyBytes.clone());
		this.sha256 = Sha2Crypt.sha256Crypt(keyBytes.clone());
		this.sha512 = Sha2Crypt.sha512Crypt(keyBytes.clone());
		Arrays.fill(keyBytes, (byte) 0);
	}

	public static boolean isCrypted(final String input) {
		if ((input == null) || input.isEmpty())
			return false;
		if (input.charAt(0) != '$')
			return false;
		if (input.startsWith("$1$") ||        // MD5
				input.startsWith("$apr1$") || // APR1
				input.startsWith("$5$") ||    // SHA2-256
				input.startsWith("$6$")) {    // SHA2-512
			return true;
		}
		return false;
	}

	public static boolean checkPassword(final String crypted, final String key) {
		String crypted2 = null;
		if (crypted == null)
			return false;
		if (crypted.length() < 24)
			return false;
		if (crypted.charAt(0) != '$')
			return false;
		final int offset2ndDolar = crypted.indexOf('$', 1);
		if (offset2ndDolar < 0)
			return false;
		final int offset3ndDolar = crypted.indexOf('$', offset2ndDolar + 1);
		if (offset3ndDolar < 0)
			return false;
		final String salt = crypted.substring(0, offset3ndDolar + 1);
		final byte[] keyBytes = key.getBytes(US_ASCII);
		if (crypted.startsWith("$1$")) { // MD5
			crypted2 = Md5Crypt.md5Crypt(keyBytes.clone(), salt);
		} else if (crypted.startsWith("$apr1$")) { // APR1
			crypted2 = Md5Crypt.apr1Crypt(keyBytes.clone(), salt);
		} else if (crypted.startsWith("$5$")) { // SHA2-256
			crypted2 = Sha2Crypt.sha256Crypt(keyBytes.clone(), salt);
		} else if (crypted.startsWith("$6$")) { // SHA2-512
			crypted2 = Sha2Crypt.sha512Crypt(keyBytes.clone(), salt);
		}
		Arrays.fill(keyBytes, (byte) 0);
		if (crypted2 == null)
			return false;
		return crypted.equals(crypted2);
	}

	@Override
	public String toString() {
		final StringBuilder sb = new StringBuilder(16 + md5.length() + apr1.length() + sha256.length()
				+ sha512.length());
		sb.append("md5=").append(md5).append(' ');
		sb.append("apr1=").append(apr1).append(' ');
		sb.append("sha256=").append(sha256).append(' ');
		sb.append("sha512=").append(sha512);
		return sb.toString();
	}

	public static void main(final String[] args) throws Throwable {
		final BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		String key = null;
		if (args.length == 0) {
			System.out.println("Enter new password: ");
			key = in.readLine().trim();
			System.out.println("Retype new password: ");
			if (!key.equals(in.readLine().trim())) {
				System.out.println("Sorry, passwords do not match");
				return;
			}
		} else {
			key = args[0];
			if (key.startsWith("-")) {
				if (key.equals("-h") || key.equals("--help")) {
					System.out.println(PasswordEncrypt.class.getName() + " [<password>]");
					return;
				}
			}
		}
		final PasswordEncrypt crypt = new PasswordEncrypt(key);
		System.out.println(crypt.toString().replace(' ', '\n'));
		// Sample:
		// plain=changeit
		// md5=$1$Ndo.HC0w$ZilSmY0T22G.haCsIKNBq1
		// apr1=$apr1$I5GYTkfO$6LN/fWivetFT0avEP9WdI/
		// sha256=$5$sVB7PKni$xyo0VYNfaWEqa8lQ5kGbwKogEoQO9w0/b/l.tS1PnUD
		// sha512=$6$/aLGYlhc$8Jn6qlvvr5i9lc2CwSCQX1qiAkEbKKfaXbhCjjRueTp4jqN1iM5o9YBJ/7u7VL2hSWE.huvUtsjH1UoVxBRXJ0
	}
}

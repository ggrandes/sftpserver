/*
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.javastack.sftpserver;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;

import javax.xml.bind.DatatypeConverter;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.Compression;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.compression.CompressionDelayedZlib;
import org.apache.sshd.common.compression.CompressionNone;
import org.apache.sshd.common.compression.CompressionZlib;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.FileSystemView;
import org.apache.sshd.common.file.SshFile;
import org.apache.sshd.common.file.nativefs.NativeFileSystemView;
import org.apache.sshd.common.file.nativefs.NativeSshFile;
import org.apache.sshd.common.mac.HMACSHA1;
import org.apache.sshd.common.mac.HMACSHA256;
import org.apache.sshd.common.mac.HMACSHA512;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.keyprovider.PEMGeneratorHostKeyProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.sftp.SftpSubsystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SFTP Server
 * 
 * @author Guillermo Grandes / guillermo.grandes[at]gmail.com
 */
public class Server implements PasswordAuthenticator, PublickeyAuthenticator {
	public static final String VERSION = "1.0.6";
	public static final String CONFIG_FILE = "/sftpd.properties";
	public static final String HOSTKEY_FILE_PEM = "keys/hostkey.pem";
	public static final String HOSTKEY_FILE_SER = "keys/hostkey.ser";

	private static final Logger LOG = LoggerFactory.getLogger(Server.class);
	private Config db;
	private SshServer sshd;

	public static void main(final String[] args) {
		new Server().start();
	}

	@SuppressWarnings("unchecked")
	protected void setupFactories() {
		sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>> asList(new SftpSubsystem.Factory()));
		sshd.setMacFactories(Arrays.<NamedFactory<Mac>> asList( //
				new HMACSHA512.Factory(), //
				new HMACSHA256.Factory(), //
				new HMACSHA1.Factory()));
	}

	protected void setupDummyShell() {
		sshd.setShellFactory(new SecureShellFactory());
	}

	protected void setupKeyPair() {
		if (SecurityUtils.isBouncyCastleRegistered()) {
			sshd.setKeyPairProvider(new PEMGeneratorHostKeyProvider(HOSTKEY_FILE_PEM));
		} else {
			sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(HOSTKEY_FILE_SER));
		}
	}

	protected void setupScp() {
		sshd.setCommandFactory(new ScpCommandFactory());
		sshd.setFileSystemFactory(new SecureFileSystemFactory(db));
		sshd.setTcpipForwardingFilter(null);
		sshd.setAgentFactory(null);
	}

	protected void setupAuth() {
		sshd.setPasswordAuthenticator(this);
		sshd.setPublickeyAuthenticator(this);
		sshd.setGSSAuthenticator(null);
	}

	@SuppressWarnings("unchecked")
	protected void setupCompress() {
		// Compression is not enabled by default
		// You need download and compile:
		// http://www.jcraft.com/jzlib/
		sshd.setCompressionFactories(Arrays.<NamedFactory<Compression>> asList( //
				new CompressionNone.Factory(), //
				new CompressionZlib.Factory(), //
				new CompressionDelayedZlib.Factory()));
	}

	protected Config loadConfig() {
		final Properties db = new Properties();
		try {
			final InputStream is = this.getClass().getResourceAsStream(CONFIG_FILE);
			if (is == null) {
				LOG.error("Config file " + CONFIG_FILE + " not found in classpath");
			} else {
				db.load(is);
				LOG.info("Config file loaded " + db.size() + " lines");
			}
		} catch (IOException e) {
			LOG.error("IOException " + e.toString(), e);
		}
		return new Config(db);

	}

	private void hackVersion() {
		// Use reflection to rewrite version info
		try {
			Class<?> c = sshd.getClass();
			Field f = null;
			while ((c != null) && (f == null)) {
				try {
					f = c.getDeclaredField("version");
					f.setAccessible(true);
					f.set(sshd, "SSHD");
					break;
				} catch (NoSuchFieldException e) {
					c = c.getSuperclass();
				}
			}
		} catch (Throwable t) {
		}
	}

	public void start() {
		LOG.info("Starting");
		db = loadConfig();
		sshd = SshServer.setUpDefaultServer();
		LOG.info("SSHD " + sshd.getVersion());
		hackVersion();
		setupFactories();
		setupKeyPair();
		setupScp();
		setupAuth();

		try {
			final int port = db.getPort();
			final boolean enableCompress = db.enableCompress();
			final boolean enableDummyShell = db.enableDummyShell();
			if (enableCompress)
				setupCompress();
			if (enableDummyShell)
				setupDummyShell();
			sshd.setPort(port);
			LOG.info("Listen on port=" + port);
			final Server thisServer = this;
			Runtime.getRuntime().addShutdownHook(new Thread() {
				public void run() {
					thisServer.stop();
				}
			});
			sshd.start();
		} catch (Exception e) {
			LOG.error("Exception " + e.toString(), e);
		}
	}

	public void stop() {
		LOG.info("Stoping");
		try {
			sshd.stop();
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		}
	}

	@Override
	public boolean authenticate(final String username, final String password, final ServerSession session) {
		LOG.info("Request auth (Password) for username=" + username);
		if ((username != null) && (password != null)) {
			return db.checkUserPassword(username, password);
		}
		return false;
	}

	@Override
	public boolean authenticate(final String username, final PublicKey key, final ServerSession session) {
		LOG.info("Request auth (PublicKey) for username=" + username);
		// File f = new File("/home/" + username + "/.ssh/authorized_keys");
		if ((username != null) && (key != null)) {
			return db.checkUserPublicKey(username, key);
		}
		return false;
	}

	// =================== Helper Classes

	static class Config {
		// Global config
		public static final String BASE = "sftpserver";
		public static final String PROP_GLOBAL = BASE + "." + "global";
		public static final String PROP_PORT = "port";
		public static final String PROP_COMPRESS = "compress";
		public static final String PROP_DUMMY_SHELL = "dummyshell";
		// User config
		public static final String PROP_BASE_USERS = BASE + "." + "user";
		public static final String PROP_PWD = "userpassword";
		public static final String PROP_KEY = "userkey" + ".";
		public static final String PROP_HOME = "homedirectory";
		public static final String PROP_ENABLED = "enableflag"; // true / false
		public static final String PROP_ENABLE_WRITE = "writepermission"; // true / false

		private final Properties db;

		public Config(final Properties db) {
			this.db = db;
		}

		public boolean enableCompress() {
			return Boolean.parseBoolean(getValue(PROP_COMPRESS));
		}

		public boolean enableDummyShell() {
			return Boolean.parseBoolean(getValue(PROP_DUMMY_SHELL));
		}

		// Global config
		public int getPort() {
			return Integer.parseInt(getValue(PROP_PORT));
		}

		private final String getValue(final String key) {
			if (key == null)
				return null;
			return db.getProperty(PROP_GLOBAL + "." + key);
		}

		// User config
		private final String getValue(final String user, final String key) {
			if ((user == null) || (key == null))
				return null;
			final String value = db.getProperty(PROP_BASE_USERS + "." + user + "." + key);
			return ((value == null) ? null : value.trim());
		}

		public boolean isEnabledUser(final String user) {
			final String value = getValue(user, PROP_ENABLED);
			if (value == null)
				return false;
			return Boolean.parseBoolean(value);
		}

		public boolean checkUserPassword(final String user, final String pwd) {
			final StringBuilder sb = new StringBuilder(96);
			boolean traceInfo = false;
			boolean authOk = false;
			sb.append("Request auth (Password) for username=").append(user).append(" ");
			try {
				if (!isEnabledUser(user)) {
					sb.append("(user disabled)");
					return authOk;
				}
				final String value = getValue(user, PROP_PWD);
				if (value == null) {
					sb.append("(no password)");
					return authOk;
				}
				final boolean isCrypted = PasswordEncrypt.isCrypted(value);
				authOk = isCrypted ? PasswordEncrypt.checkPassword(value, pwd) : value.equals(pwd);
				sb.append(isCrypted ? "(encrypted)" : "(unencrypted)");
				traceInfo = isCrypted;
			} finally {
				sb.append(": ").append(authOk ? "OK" : "FAIL");
				if (authOk) {
					if (traceInfo) {
						LOG.info(sb.toString());
					} else {
						LOG.warn(sb.toString());
					}
				} else {
					LOG.error(sb.toString());
				}
			}
			return authOk;
		}

		public boolean checkUserPublicKey(final String user, final PublicKey key) {
			final String encodedKey = PublicKeyHelper.getEncodedPublicKey(key);
			final StringBuilder sb = new StringBuilder(96);
			boolean authOk = false;
			sb.append("Request auth (PublicKey) for username=").append(user);
			sb.append(" (").append(key.getAlgorithm()).append(")");
			try {
				if (!isEnabledUser(user)) {
					sb.append(" (user disabled)");
					return authOk;
				}
				for (int i = 1; i < 1024; i++) {
					final String value = getValue(user, PROP_KEY + i);
					if (value == null) {
						if (i == 1)
							sb.append(" (no publickey)");
						break;
					} else if (value.equals(encodedKey)) {
						authOk = true;
						break;
					}
				}
			} finally {
				sb.append(": ").append(authOk ? "OK" : "FAIL");
				if (authOk) {
					LOG.info(sb.toString());
				} else {
					LOG.error(sb.toString());
				}
			}
			return authOk;
		}

		public String getHome(final String user) {
			try {
				final File home = new File(getValue(user, PROP_HOME));
				if (home.isDirectory() && home.canRead()) {
					return home.getCanonicalPath();
				}
			} catch (IOException e) {
			}
			return null;
		}

		public boolean hasWritePerm(final String user) {
			final String value = getValue(user, PROP_ENABLE_WRITE);
			return Boolean.parseBoolean(value);
		}
	}

	static class SecureShellFactory implements Factory<Command> {
		@Override
		public Command create() {
			return new SecureShellCommand();
		}
	}

	static class SecureShellCommand implements Command {
		private OutputStream err = null;
		private ExitCallback callback = null;

		@Override
		public void setInputStream(final InputStream in) {
		}

		@Override
		public void setOutputStream(final OutputStream out) {
		}

		@Override
		public void setErrorStream(final OutputStream err) {
			this.err = err;
		}

		@Override
		public void setExitCallback(final ExitCallback callback) {
			this.callback = callback;
		}

		@Override
		public void start(final Environment env) throws IOException {
			if (err != null) {
				err.write("shell not allowed\r\n".getBytes("ISO-8859-1"));
				err.flush();
			}
			if (callback != null)
				callback.onExit(-1, "shell not allowed");
		}

		@Override
		public void destroy() {
		}
	}

	// =================== Extended NativeFileSystem

	static class SecureFileSystemFactory implements FileSystemFactory {
		private final Config db;

		public SecureFileSystemFactory(final Config db) {
			this.db = db;
		}

		@Override
		public FileSystemView createFileSystemView(final Session session) throws IOException {
			final String userName = session.getUsername();
			final String home = db.getHome(userName);
			if (home == null) {
				throw new IOException("user home error");
			}
			return new SecureFileSystemView(home, userName, !db.hasWritePerm(userName));
		}
	}

	static class SecureFileSystemView extends NativeFileSystemView {
		private static final boolean caseInsensitive = false;
		private final String rootDir;
		private final String userName;
		private final boolean isReadOnly;

		public SecureFileSystemView(final String rootDir, final String userName, final boolean isReadOnly) {
			super(userName, Collections.singletonMap("/", "/"), "/", File.pathSeparatorChar, caseInsensitive);
			this.rootDir = SecureSshFile.normalizeSeparateChar(rootDir);
			this.userName = userName;
			this.isReadOnly = isReadOnly;
		}

		@Override
		public FileSystemView getNormalizedView() {
			return this;
		}

		@Override
		public SshFile getFile(final String file) {
			return getFile("/", file);
		}

		@Override
		public SshFile getFile(final SshFile baseDir, final String file) {
			return getFile(baseDir.getAbsolutePath(), file);
		}

		protected SshFile getFile(final String dir, final String file) {
			final String physicalName = SecureSshFile.getPhysicalName(rootDir, dir, file, caseInsensitive);
			final File fileObj = new File(physicalName);
			return new SecureSshFile(this, file, fileObj, userName, isReadOnly);
		}
	}

	static class SecureSshFile extends NativeSshFile {
		final boolean isReadOnly;

		public SecureSshFile(final SecureFileSystemView fileSystemView, final String fileName,
				final File file, final String userName, final boolean isReadOnly) {
			super(fileSystemView, fileName, file, userName);
			this.isReadOnly = isReadOnly;
		}

		@Override
		public boolean isRemovable() {
			return isWritable();
		}

		@Override
		public boolean isWritable() {
			if (isReadOnly)
				return false;
			return super.isWritable();
		}

		@Override
		public boolean mkdir() {
			if (isReadOnly)
				return false;
			return super.mkdir();
		}

		@Override
		public boolean delete() {
			if (isReadOnly)
				return false;
			return super.delete();
		}

		@Override
		public boolean create() throws IOException {
			if (isReadOnly)
				return false;
			return super.create();
		}

		@Override
		public void truncate() throws IOException {
			if (isReadOnly)
				return;
		}

		@Override
		public boolean move(final SshFile destination) {
			if (isReadOnly)
				return false;
			return super.move(destination);
		}

		@Override
		public void setAttributes(final Map<Attribute, Object> attributes) throws IOException {
			if (isReadOnly)
				return;
			super.setAttributes(attributes);
		}

		@Override
		public void setAttribute(final Attribute attribute, final Object value) throws IOException {
			if (isReadOnly)
				return;
			super.setAttribute(attribute, value);
		}

		@Override
		public void createSymbolicLink(final SshFile destination) throws IOException {
			if (isReadOnly)
				return;
			super.createSymbolicLink(destination);
		}
	}

	// =================== PublicKeyHelper

	static class PublicKeyHelper {
		private static final Charset US_ASCII = Charset.forName("US-ASCII");

		public static String getEncodedPublicKey(final PublicKey pub) {
			if (pub instanceof RSAPublicKey) {
				return encodeRSAPublicKey((RSAPublicKey) pub);
			}
			if (pub instanceof DSAPublicKey) {
				return encodeDSAPublicKey((DSAPublicKey) pub);
			}
			return null;
		}

		public static String encodeRSAPublicKey(final RSAPublicKey key) {
			final BigInteger[] params = new BigInteger[] {
					key.getPublicExponent(), key.getModulus()
			};
			return encodePublicKey(params, "ssh-rsa");
		}

		public static String encodeDSAPublicKey(final DSAPublicKey key) {
			final BigInteger[] params = new BigInteger[] {
					key.getParams().getP(), key.getParams().getQ(), key.getParams().getG(), key.getY()
			};
			return encodePublicKey(params, "ssh-dss");
		}

		private static final void encodeUInt32(final IoBuffer bab, final int value) {
			bab.put((byte) ((value >> 24) & 0xFF));
			bab.put((byte) ((value >> 16) & 0xFF));
			bab.put((byte) ((value >> 8) & 0xFF));
			bab.put((byte) (value & 0xFF));
		}

		private static String encodePublicKey(final BigInteger[] params, final String keyType) {
			final IoBuffer bab = IoBuffer.allocate(256);
			bab.setAutoExpand(true);
			byte[] buf = null;
			// encode the header "ssh-dss" / "ssh-rsa"
			buf = keyType.getBytes(US_ASCII); // RFC-4253, pag.13
			encodeUInt32(bab, buf.length);    // RFC-4251, pag.8 (string encoding)
			for (final byte b : buf) {
				bab.put(b);
			}
			// encode params
			for (final BigInteger param : params) {
				buf = param.toByteArray();
				encodeUInt32(bab, buf.length);
				for (final byte b : buf) {
					bab.put(b);
				}
			}
			bab.flip();
			buf = new byte[bab.limit()];
			System.arraycopy(bab.array(), 0, buf, 0, buf.length);
			bab.free();
			return keyType + " " + DatatypeConverter.printBase64Binary(buf);
		}

	}
}

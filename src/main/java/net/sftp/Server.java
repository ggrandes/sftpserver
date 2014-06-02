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
package net.sftp;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Properties;
import org.apache.sshd.SshServer;
import org.apache.sshd.common.Compression;
import org.apache.sshd.common.Factory;
import org.apache.sshd.common.Mac;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.Session;
import org.apache.sshd.common.compression.CompressionDelayedZlib;
import org.apache.sshd.common.compression.CompressionNone;
import org.apache.sshd.common.compression.CompressionZlib;
import org.apache.sshd.common.mac.HMACSHA1;
import org.apache.sshd.common.util.SecurityUtils;
import org.apache.sshd.server.Command;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.FileSystemFactory;
import org.apache.sshd.server.FileSystemView;
import org.apache.sshd.server.PasswordAuthenticator;
import org.apache.sshd.server.PublickeyAuthenticator;
import org.apache.sshd.server.SshFile;
import org.apache.sshd.server.command.ScpCommandFactory;
import org.apache.sshd.server.filesystem.NativeSshFile;
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
	public static final String VERSION = "1.0.1";
	public static final String CONFIG_FILE = "/sftpd.properties";
	public static final String HOSTKEY_FILE_PEM = "keys/hostkey.pem";
	public static final String HOSTKEY_FILE_SER = "keys/hostkey.ser";
	//
	private final Logger LOG = LoggerFactory.getLogger(Server.class);
	private Config db;
	private SshServer sshd;
	//
	public static void main(final String[] args) {
		new Server().start();
	}
	@SuppressWarnings("unchecked")
	protected void setupFactories() {
		sshd.setSubsystemFactories(Arrays.<NamedFactory<Command>>asList(new SftpSubsystem.Factory()));
		sshd.setMacFactories(Arrays.<NamedFactory<Mac>>asList(new HMACSHA1.Factory()));
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
		sshd.setForwardingFilter(null);
	}
	protected void setupAuth() {
		sshd.setPasswordAuthenticator(this);
		sshd.setPublickeyAuthenticator(null);
		sshd.setGSSAuthenticator(null);
	}
	@SuppressWarnings("unchecked")
	protected void setupCompress() {
		// Compression is not enabled by default
		// You need download and compile:
		// http://www.jcraft.com/jzlib/
		sshd.setCompressionFactories(Arrays.<NamedFactory<Compression>>asList(
				new CompressionNone.Factory(),
				new CompressionZlib.Factory(),
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
				} catch(NoSuchFieldException e) {
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
		//
		try {
			final int port = db.getPort();
			final boolean enableCompress = db.enableCompress();
			final boolean enableDummyShell = db.enableDummyShell();
			if (enableCompress)
				setupCompress();
			if (enableDummyShell)
				setupDummyShell();
			sshd.setPort(port);
			sshd.setReuseAddress(true);
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
		//File f = new File("/home/" + username + "/.ssh/authorized_keys");
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
		public static final String PROP_HOME = "homedirectory";
		public static final String PROP_ENABLED = "enableflag"; // true / false
		public static final String PROP_ENABLE_WRITE = "writepermission"; // true / false
		//
		private final Properties db;
		//
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
			return db.getProperty(PROP_BASE_USERS + "." + user + "." + key);			
		}
		public boolean isEnabledUser(final String user) {
			final String value = getValue(user, PROP_ENABLED);
			if (value == null)
				return false;
			return Boolean.parseBoolean(value);
		}
		public boolean checkUserPassword(final String user, final String pwd) {
			if (pwd == null)
				return false;
			if (!isEnabledUser(user)) {
				return false;
			}
			final String value = getValue(user, PROP_PWD);
			if (value == null)
				return false;
			return (value.equals(pwd));
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
		//
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
		//
		public SecureFileSystemFactory(final Config db) {
			this.db = db;
		}
		//
		@Override
		public FileSystemView createFileSystemView(final Session session)
				throws IOException {
			final String userName = session.getUsername();
			final String home = db.getHome(userName);
			if (home == null) {
				throw new IOException("user home error");
			}
			return new SecureFileSystemView(home, userName, !db.hasWritePerm(userName));
		}
	}

	static class SecureFileSystemView implements FileSystemView {
		// the first and the last character will always be '/'
		// It is always with respect to the root directory.
		private String currDir = "/";
		private String rootDir = "/";
		private String userName;
		private boolean isReadOnly = true;
		private boolean caseInsensitive = false;
		//
		public SecureFileSystemView(final String rootDir, final String userName, final boolean isReadOnly) {
			this.rootDir = SecureSshFile.normalizeSeparateChar(rootDir);
			this.userName = userName;
			this.isReadOnly = isReadOnly;
		}
		//
		@Override
		public SshFile getFile(final String file) {
			return getFile(currDir, file);
		}
		@Override
		public SshFile getFile(final SshFile baseDir, final String file) {
			return getFile(baseDir.getAbsolutePath(), file);
		}
		//
		protected SshFile getFile(final String dir, final String file) {
			// get actual file object
			String physicalName = SecureSshFile.getPhysicalName("/", dir, file, caseInsensitive);
			File fileObj = new File(rootDir, physicalName); // chroot

			// strip the root directory and return
			String userFileName = physicalName.substring("/".length() - 1);
			return new SecureSshFile(userFileName, fileObj, userName, isReadOnly);
		}
	}

	static class SecureSshFile extends NativeSshFile {
		final boolean isReadOnly;
		//
		public SecureSshFile(final String fileName, final File file, final String userName, final boolean isReadOnly) {
			super(fileName, file, userName);
			this.isReadOnly = isReadOnly;
		}
		//
		public boolean isWritable() {
			if (isReadOnly)
				return false;
			return super.isWritable();
		}
	}
}

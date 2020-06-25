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

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.PosixFilePermission;
import java.security.Principal;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.PropertyResolver;
import org.apache.sshd.common.PropertyResolverUtils;
import org.apache.sshd.common.cipher.BuiltinCiphers;
import org.apache.sshd.common.compression.BuiltinCompressions;
import org.apache.sshd.common.compression.Compression;
import org.apache.sshd.common.config.SshConfigFileReader;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.file.FileSystemFactory;
import org.apache.sshd.common.file.root.RootedFileSystemProvider;
import org.apache.sshd.common.kex.BuiltinDHFactories;
import org.apache.sshd.common.mac.BuiltinMacs;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.ServerBuilder;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.channel.ChannelSessionFactory;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.keyprovider.AbstractGeneratorHostKeyProvider;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.scp.ScpCommandFactory;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.shell.ShellFactory;
import org.apache.sshd.server.subsystem.sftp.SftpFileSystemAccessor;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemProxy;
import org.javastack.sftpserver.readonly.ReadOnlyRootedFileSystemProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SFTP Server
 * 
 * @author Guillermo Grandes / guillermo.grandes[at]gmail.com
 */
public class Server implements PasswordAuthenticator, PublickeyAuthenticator {
	public static final String CONFIG_FILE = "/sftpd.properties";
	public static final String HTPASSWD_FILE = "/htpasswd";
	public static final String HOSTKEY_FILE_PEM = "keys/hostkey.pem";
	public static final String HOSTKEY_FILE_SER = "keys/hostkey.ser";

	private static final Logger LOG = LoggerFactory.getLogger(Server.class);
	private Config db;
	private SshServer sshd;
	private volatile boolean running = true;

	public static void main(final String[] args) {
		new Server().start();
	}

	protected void setupFactories() {
		final SftpSubsystemFactory sftpSubsys = new SftpSubsystemFactory.Builder()
				.withFileSystemAccessor(new CustomSftpFileSystemAccessor()).build();
		// org.apache.sshd.common.BaseBuilder
		sshd.setSubsystemFactories(Collections.singletonList(sftpSubsys));
		sshd.setChannelFactories(Collections.singletonList(ChannelSessionFactory.INSTANCE));
		// NOTE: Not all of these are supported by sshd-core
		// man 5 sshd_config : Ciphers
		// org.apache.sshd.common.config.ConfigFileReaderSupport.DEFAULT_CIPHERS
		SshConfigFileReader.configureCiphers(sshd, //
				"chacha20-poly1305@openssh.com," + //
						"aes128-ctr,aes192-ctr,aes256-ctr," + //
						"aes128-gcm@openssh.com,aes256-gcm@openssh.com", //
				true, true);
		// man 5 sshd_config : KexAlgorithms
		// org.apache.sshd.common.config.ConfigFileReaderSupport.DEFAULT_KEX_ALGORITHMS
		SshConfigFileReader.configureKeyExchanges(sshd, //
				"curve25519-sha256,curve25519-sha256@libssh.org," + //
						"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521," + //
						"diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1", //
				true, ServerBuilder.DH2KEX, true);
		// man 5 sshd_config : MACs
		// org.apache.sshd.common.config.ConfigFileReaderSupport.DEFAULT_MACS
		SshConfigFileReader.configureMacs(sshd, //
				"umac-64-etm@openssh.com,umac-128-etm@openssh.com," + //
						"hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com," + //
						"hmac-sha1-etm@openssh.com," + //
						"umac-64@openssh.com,umac-128@openssh.com," + //
						"hmac-sha2-256,hmac-sha2-512,hmac-sha1", //
				true, true);
	}

	protected void setupDummyShell(final boolean enable) {
		sshd.setShellFactory(enable ? new SecureShellFactory() : null);
	}

	protected void setupKeyPair() {
		final AbstractGeneratorHostKeyProvider provider;
		if (SecurityUtils.isBouncyCastleRegistered()) {
			provider = SecurityUtils.createGeneratorHostKeyProvider(Paths.get(HOSTKEY_FILE_PEM));
		} else {
			provider = new SimpleGeneratorHostKeyProvider(Paths.get(HOSTKEY_FILE_SER));
		}
		provider.setAlgorithm(KeyUtils.RSA_ALGORITHM);
		sshd.setKeyPairProvider(provider);
	}

	protected void setupScp() {
		sshd.setCommandFactory(new ScpCommandFactory());
		sshd.setFileSystemFactory(new SecureFileSystemFactory(db));
		sshd.setForwardingFilter(null);
		sshd.setAgentFactory(null);
	}

	protected void setupAuth() {
		sshd.setPasswordAuthenticator(this);
		sshd.setPublickeyAuthenticator(this);
		sshd.setGSSAuthenticator(null);
	}

	protected void setupSysprops() {
		sshd.setParentPropertyResolver(PropertyResolver.EMPTY);
	}

	protected void loadHtPasswd() throws IOException {
		InputStream is = null;
		BufferedReader r = null;
		try {
			final boolean htEnabled = Boolean.parseBoolean(db.getHtValue(Config.PROP_HT_ENABLED));
			if (!htEnabled) {
				return;
			}
			final String htHome = db.getHtValue(Config.PROP_HT_HOME);
			final boolean htEnableWrite = Boolean.parseBoolean(db.getHtValue(Config.PROP_HT_ENABLE_WRITE));
			is = getClass().getResourceAsStream(HTPASSWD_FILE);
			r = new BufferedReader(new InputStreamReader(is));
			if (is == null) {
				LOG.error("htpasswd file " + HTPASSWD_FILE + " not found in classpath");
				return;
			}
			String line = null;
			int c = 0;
			while ((line = r.readLine()) != null) {
				if (line.startsWith("#"))
					continue;
				final String[] tok = line.split(":", 2);
				if (tok.length != 2)
					continue;
				final String user = tok[0];
				final String auth = tok[1];
				db.setValue(user, Config.PROP_PWD, auth);
				db.setValue(user, Config.PROP_HOME, htHome);
				db.setValue(user, Config.PROP_ENABLED, htEnabled);
				db.setValue(user, Config.PROP_ENABLE_WRITE, htEnableWrite);
				c++;
			}
			LOG.info("htpasswd file loaded " + c + " lines");
		} finally {
			closeQuietly(r);
			closeQuietly(is);
		}
	}

	protected void setupCompress(final boolean enable) {
		// Compression is not enabled by default
		// You need download and compile:
		// http://www.jcraft.com/jzlib/
		if (enable) {
			sshd.setCompressionFactories(Arrays.<NamedFactory<Compression>>asList( //
					BuiltinCompressions.none, //
					BuiltinCompressions.zlib, //
					BuiltinCompressions.delayedZlib));
		} else {
			sshd.setCompressionFactories(Arrays.<NamedFactory<Compression>>asList( //
					BuiltinCompressions.none));
		}
	}

	protected Config loadConfig() {
		final Properties db = new Properties();
		InputStream is = null;
		try {
			is = getClass().getResourceAsStream(CONFIG_FILE);
			if (is == null) {
				LOG.error("Config file " + CONFIG_FILE + " not found in classpath");
			} else {
				db.load(is);
				LOG.info("Config file loaded " + db.size() + " lines");
			}
		} catch (IOException e) {
			LOG.error("IOException " + e.toString(), e);
		} finally {
			closeQuietly(is);
		}
		return new Config(db);

	}

	private void closeQuietly(final Closeable c) {
		if (c != null) {
			try {
				c.close();
			} catch (Exception ign) {
			}
		}
	}

	private void hackVersion() {
		PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.SERVER_IDENTIFICATION, "SSHD");
	}

	public void start() {
		LOG.info("Starting");
		db = loadConfig();
		LOG.info("BouncyCastle enabled=" + SecurityUtils.isBouncyCastleRegistered());
		sshd = SshServer.setUpDefaultServer();
		LOG.info("SSHD " + sshd.getVersion());
		hackVersion();
		setupFactories();
		setupKeyPair();
		setupScp();
		setupAuth();
		setupSysprops();

		try {
			final int port = db.getPort();
			final boolean enableCompress = db.enableCompress();
			final boolean enableDummyShell = db.enableDummyShell();
			setupCompress(enableCompress);
			setupDummyShell(enableDummyShell);
			loadHtPasswd();
			sshd.setPort(port);
			LOG.info("Listen on port=" + port);
			final Server thisServer = this;
			Runtime.getRuntime().addShutdownHook(new Thread() {
				public void run() {
					thisServer.stop();
				}
			});
			sshd.start();
			LOG.info("KeyExchangeFactories(available): " + NamedResource.getNameList(BuiltinDHFactories.VALUES));
			LOG.info("MacFactories(available): " + NamedResource.getNameList(BuiltinMacs.VALUES));
			LOG.info("CipherFactories(available): " + NamedResource.getNameList(BuiltinCiphers.VALUES));
			LOG.info("KeyExchangeFactories(enabled): " + NamedResource.getNameList(sshd.getKeyExchangeFactories()));
			LOG.info("MacFactories(enabled): " + NamedResource.getNameList(sshd.getMacFactories()));
			LOG.info("CipherFactories(enabled): " + NamedResource.getNameList(sshd.getCipherFactories()));
		} catch (Exception e) {
			LOG.error("Exception " + e.toString(), e);
		}
		while (running) {
			try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}

	public void stop() {
		LOG.info("Stopping");
		running = false;
		try {
			sshd.stop();
		} catch (IOException e) {
			try {
				sshd.stop(true);
			} catch (IOException ee) {
				LOG.error("Failed to stop", ee);
			}
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
		public static final String PROP_MAX_PACKET_LENGTH = "maxPacketLength";
		// HtPasswd config
		public static final String PROP_HTPASSWD = BASE + "." + "htpasswd";
		public static final String PROP_HT_HOME = "homedirectory";
		public static final String PROP_HT_ENABLED = "enableflag";
		public static final String PROP_HT_ENABLE_WRITE = "writepermission"; // true / false
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

		// Global config
		public boolean enableCompress() {
			return Boolean.parseBoolean(getValue(PROP_COMPRESS));
		}

		public boolean enableDummyShell() {
			return Boolean.parseBoolean(getValue(PROP_DUMMY_SHELL));
		}

		public int getPort() {
			return Integer.parseInt(getValue(PROP_PORT));
		}

		private final String getValue(final String key) {
			if (key == null)
				return null;
			return db.getProperty(PROP_GLOBAL + "." + key);
		}

		private final String getHtValue(final String key) {
			if (key == null)
				return null;
			return db.getProperty(PROP_HTPASSWD + "." + key);
		}

		// User config
		private final String getValue(final String user, final String key) {
			if ((user == null) || (key == null))
				return null;
			final String value = db.getProperty(PROP_BASE_USERS + "." + user + "." + key);
			return ((value == null) ? null : value.trim());
		}

		private final void setValue(final String user, final String key, final Object value) {
			if ((user == null) || (key == null) || (value == null))
				return;
			db.setProperty(PROP_BASE_USERS + "." + user + "." + key, String.valueOf(value));
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
			final String encodedKey = PublicKeyEntry.toString(key);
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
					} else {
						// Strip comment in keys
						// ssh-rsa AAAAB3NzaC1y...E7uQ== root@host
						final int s1 = value.indexOf(' ', 0);
						final int s2 = value.indexOf(' ', s1 + 1);
						final String ukey = (s2 > s1 ? value.substring(0, s2) : value);
						if (ukey.equals(encodedKey)) {
							authOk = true;
							break;
						}
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

	static class SecureShellFactory implements ShellFactory {
		@Override
		public Command createShell(final ChannelSession channel) throws IOException {
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
		public void start(final ChannelSession channel, final Environment env) throws IOException {
			if (err != null) {
				err.write("shell not allowed\r\n".getBytes("ISO-8859-1"));
				err.flush();
			}
			if (callback != null)
				callback.onExit(-1, "shell not allowed");
		}

		@Override
		public void destroy(final ChannelSession channel) {
		}
	}

	static class CustomSftpFileSystemAccessor implements SftpFileSystemAccessor {
		@Override
		public void setFileAttribute(final ServerSession session, final SftpSubsystemProxy subsystem, final Path file,
				final String view, final String attribute, final Object value, final LinkOption... options)
				throws IOException {
			throw new UnsupportedOperationException("Attribute set not supported for " + file);
		}

		@Override
		public void setFileOwner(final ServerSession session, final SftpSubsystemProxy subsystem, final Path file,
				final Principal value, final LinkOption... options) throws IOException {
			throw new UnsupportedOperationException("Owner set not supported for " + file);
		}

		@Override
		public void setGroupOwner(final ServerSession session, final SftpSubsystemProxy subsystem, final Path file,
				final Principal value, final LinkOption... options) throws IOException {
			throw new UnsupportedOperationException("Group set not supported");
		}

		@Override
		public void setFilePermissions(final ServerSession session, final SftpSubsystemProxy subsystem, final Path file,
				final Set<PosixFilePermission> perms, final LinkOption... options) throws IOException {
			throw new UnsupportedOperationException("Permissions set not supported");
		}

		@Override
		public void setFileAccessControl(final ServerSession session, final SftpSubsystemProxy subsystem,
				final Path file, final List<AclEntry> acl, final LinkOption... options) throws IOException {
			throw new UnsupportedOperationException("ACL set not supported");
		}

		@Override
		public void createLink(final ServerSession session, final SftpSubsystemProxy subsystem, final Path link,
				final Path existing, final boolean symLink) throws IOException {
			throw new UnsupportedOperationException("Link not supported");
		}

		@Override
		public String toString() {
			return SftpFileSystemAccessor.class.getSimpleName() + "[CUSTOM]";
		}
	}

	static class SecureFileSystemFactory implements FileSystemFactory {
		private final Config db;

		public SecureFileSystemFactory(final Config db) {
			this.db = db;
		}

		@Override
		public FileSystem createFileSystem(final SessionContext session) throws IOException {
			final String userName = session.getUsername();
			final String home = db.getHome(userName);
			if (home == null) {
				throw new IOException("user home error");
			}
			final RootedFileSystemProvider rfsp = db.hasWritePerm(userName) ? new RootedFileSystemProvider()
					: new ReadOnlyRootedFileSystemProvider();
			return rfsp.newFileSystem(Paths.get(home), Collections.<String, Object>emptyMap());
		}

		@Override
		public Path getUserHomeDir(final SessionContext session) throws IOException {
			final String userName = session.getUsername();
			final String home = db.getHome(userName);
			if (home == null) {
				throw new IOException("user home error");
			}
			return Paths.get(home);
		}
	}
}

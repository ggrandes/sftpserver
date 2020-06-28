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
import java.net.URL;
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
import java.util.concurrent.TimeUnit;

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
import org.apache.sshd.common.session.SessionHeartbeatController.HeartbeatType;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.ServerBuilder;
import org.apache.sshd.server.ServerFactoryManager;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.password.PasswordAuthenticator;
import org.apache.sshd.server.auth.pubkey.CachingPublicKeyAuthenticator;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.channel.ChannelSessionFactory;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.kex.Moduli;
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
import org.slf4j.event.Level;

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
	private ServiceLogger logger;
	private volatile boolean running = true;

	public static void main(final String[] args) {
		new Server().start();
	}

	protected void setupFactories() {
		final SftpSubsystemFactory sftpSubsys = new SftpSubsystemFactory.Builder()
				.withFileSystemAccessor(new CustomSftpFileSystemAccessor()).build();
		// Request logger
		sftpSubsys.addSftpEventListener(logger);
		// Session logger
		sshd.addSessionListener(logger);
		// org.apache.sshd.common.BaseBuilder
		sshd.setSubsystemFactories(Collections.singletonList(sftpSubsys));
		sshd.setChannelFactories(Collections.singletonList(ChannelSessionFactory.INSTANCE));
		SshConfigFileReader.configureKeyExchanges(sshd, //
				db.getKexAlgorithms(), //
				true, ServerBuilder.DH2KEX, true);
		SshConfigFileReader.configureCiphers(sshd, //
				db.getCiphers(), //
				true, true);
		SshConfigFileReader.configureMacs(sshd, //
				db.getMacs(), //
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
		final int hb = db.getHeartbeat();
		if (hb <= 0) {
			sshd.disableSessionHeartbeat();
		} else {
			sshd.setSessionHeartbeat(HeartbeatType.IGNORE, TimeUnit.SECONDS, hb);
		}
	}

	protected void setupAuth() {
		sshd.setPasswordAuthenticator(this);
		sshd.setPublickeyAuthenticator(new CachingPublicKeyAuthenticator(this));
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
		return new Config(db, logger);

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

	/**
	 * Filter the moduli file contains prime numbers and generators used by
	 * Diffie-Hellman Group Exchange.
	 * 
	 * @see org.apache.sshd.common.kex.BuiltinDHFactories#dhgex256
	 *      diffie-hellman-group-exchange-sha256
	 * @see org.apache.sshd.common.kex.BuiltinDHFactories#dhgex
	 *      diffie-hellman-group-exchange-sha1
	 * @see org.apache.sshd.server.kex.DHGEXServer
	 * @see org.apache.sshd.server.kex.Moduli
	 * @see http://manpages.ubuntu.com/manpages/focal/man5/moduli.5.html
	 */
	private void hackModuliDHGEX() {
		URL srcModuli = null;
		final File sysLinuxModuli = new File("/etc/ssh/moduli");
		if (sysLinuxModuli.canRead()) {
			try {
				srcModuli = sysLinuxModuli.toURI().toURL();
				LOG.info("Linux moduli file: " + sysLinuxModuli);
			} catch (IOException e) {
			}
		} else {
			final String moduliPath = Moduli.INTERNAL_MODULI_RESPATH;
			srcModuli = Moduli.class.getResource(moduliPath);
			if (srcModuli == null) {
				LOG.warn("Missing internal moduli file: " + moduliPath);
			}
		}
		if (srcModuli != null) {
			final File newModuli = new File(System.getProperty("java.io.tmpdir", "/tmp/"), "moduli.sftpd");
			if (!newModuli.exists() // create
					|| (newModuli.length() <= 0) // empty
					|| (System.currentTimeMillis() - newModuli.lastModified() > TimeUnit.DAYS.toMillis(1))) { // 1day
				try {
					LOG.info("Filtering moduli file:" + srcModuli.toExternalForm());
					final List<String> data = ModuliFilter.filterModuli(srcModuli, //
							db.getMinSizeDHGEX(), db.getMaxSizeDHGEX());
					ModuliFilter.writeModuli(newModuli, data);
				} catch (IOException e) {
					LOG.error("Error filtering moduli: " + e, e);
				}
			}
			if ((newModuli != null) && newModuli.canRead() && (newModuli.length() > 0)) {
				LOG.warn("Using moduli file: " + newModuli);
				PropertyResolverUtils.updateProperty(sshd, ServerFactoryManager.MODULI_URL,
						newModuli.toURI().toString());
			}
		}
	}

	public void start() {
		LOG.info("Starting");
		logger = new ServiceLogger();
		db = loadConfig();
		LOG.info("BouncyCastle enabled=" + SecurityUtils.isBouncyCastleRegistered());
		sshd = SshServer.setUpDefaultServer();
		LOG.info("SSHD " + sshd.getVersion());
		hackVersion();
		hackModuliDHGEX();
		setupFactories();
		setupKeyPair();
		setupScp();
		setupAuth();
		setupSysprops();

		try {
			final String host = db.getHost();
			final int port = db.getPort();
			final boolean enableCompress = db.enableCompress();
			final boolean enableDummyShell = db.enableDummyShell();
			setupCompress(enableCompress);
			setupDummyShell(enableDummyShell);
			loadHtPasswd();
			logger.setLogRequest(db.enableLogRequest());
			sshd.setHost(host);
			sshd.setPort(port);
			LOG.info("Listen on host=" + host + " port=" + port);
			final Server thisServer = this;
			Runtime.getRuntime().addShutdownHook(new Thread() {
				public void run() {
					thisServer.stop();
				}
			});
			sshd.start();
			LOG.info("KexAlgorithms(available): " + NamedResource.getNameList(BuiltinDHFactories.VALUES));
			LOG.info("Ciphers(available): " + NamedResource.getNameList(BuiltinCiphers.VALUES));
			LOG.info("Macs(available): " + NamedResource.getNameList(BuiltinMacs.VALUES));
			LOG.info("KexAlgorithms(enabled): " + NamedResource.getNameList(sshd.getKeyExchangeFactories()));
			LOG.info("Ciphers(enabled): " + NamedResource.getNameList(sshd.getCipherFactories()));
			LOG.info("Macs(enabled): " + NamedResource.getNameList(sshd.getMacFactories()));
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
		logger.authPasswordPreLogin(session, username);
		if ((username != null) && (password != null)) {
			return db.checkUserPassword(session, username, password);
		}
		logger.authPasswordPostLogin(session, username, Level.ERROR, "[null data][FAIL]");
		return false;
	}

	@Override
	public boolean authenticate(final String username, final PublicKey key, final ServerSession session) {
		logger.authPublicKeyPreLogin(session, username, key);
		// File f = new File("/home/" + username + "/.ssh/authorized_keys");
		if ((username != null) && (key != null)) {
			return db.checkUserPublicKey(session, username, key);
		}
		logger.authPublicKeyPostLogin(session, username, key, Level.ERROR, "[null data][FAIL]");
		return false;
	}

	// =================== Helper Classes

	static class Config {
		// @see https://stribika.github.io/2015/01/04/secure-secure-shell.html
		// @see http://manpages.ubuntu.com/manpages/focal/man5/sshd_config.5.html
		public static final int DEFAULT_DHGEX_MIN = 2000;
		public static final int DEFAULT_DHGEX_MAX = 8200;
		/**
		 * man 5 sshd_config : KexAlgorithms
		 * 
		 * @see org.apache.sshd.common.config.ConfigFileReaderSupport#DEFAULT_KEX_ALGORITHMS
		 * @see org.apache.sshd.common.kex.BuiltinDHFactories
		 * @implNote Not all kex/ciphers/macs are supported by sshd-core
		 */
		public static final String DEFAULT_KEX_ALGORITHMS = "curve25519-sha256,curve25519-sha256@libssh.org," + //
				"diffie-hellman-group14-sha256," + //
				"diffie-hellman-group16-sha512," + //
				"diffie-hellman-group-exchange-sha256," + //
				"ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521," + //
				"diffie-hellman-group14-sha1";
		/**
		 * man 5 sshd_config : Ciphers
		 * 
		 * @see org.apache.sshd.common.config.ConfigFileReaderSupport#DEFAULT_CIPHERS
		 * @see org.apache.sshd.common.cipher.BuiltinCiphers
		 * @implNote Not all kex/ciphers/macs are supported by sshd-core
		 */
		public static final String DEFAULT_CIPHERS = "chacha20-poly1305@openssh.com," + //
				"aes128-ctr,aes192-ctr,aes256-ctr," + //
				"aes128-gcm@openssh.com,aes256-gcm@openssh.com";
		/**
		 * man 5 sshd_config : MACs
		 * 
		 * @see org.apache.sshd.common.config.ConfigFileReaderSupport#DEFAULT_MACS
		 * @see org.apache.sshd.common.mac.BuiltinMacs
		 * @implNote Not all kex/ciphers/macs are supported by sshd-core
		 */
		public static final String DEFAULT_MACS = "umac-64-etm@openssh.com,umac-128-etm@openssh.com," + //
				"hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com," + //
				"hmac-sha1-etm@openssh.com," + //
				"umac-64@openssh.com,umac-128@openssh.com," + //
				"hmac-sha2-256,hmac-sha2-512,hmac-sha1";
		public static final int DEFAULT_HEARTBEAT = 0;
		// Global config
		public static final String BASE = "sftpserver";
		public static final String PROP_GLOBAL = BASE + "." + "global";
		public static final String PROP_HOST = "host";
		public static final String PROP_PORT = "port";
		public static final String PROP_COMPRESS = "compress";
		public static final String PROP_DUMMY_SHELL = "dummyshell";
		public static final String PROP_LOG_REQUEST = "logrequest";
		public static final String PROP_HEARTBEAT = "heartbeat";
		public static final String PROP_KEX_ALGORITHMS = "kexalgorithms";
		public static final String PROP_CIPHERS = "ciphers";
		public static final String PROP_MACS = "macs";
		public static final String PROP_DHGEX_MIN = "dhgex-min";
		public static final String PROP_DHGEX_MAX = "dhgex-max";
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
		private final ServiceLogger logger;

		public Config(final Properties db, final ServiceLogger logger) {
			this.db = db;
			this.logger = logger;
		}

		// Global config
		public boolean enableCompress() {
			return Boolean.parseBoolean(getValue(PROP_COMPRESS));
		}

		public boolean enableDummyShell() {
			return Boolean.parseBoolean(getValue(PROP_DUMMY_SHELL));
		}

		public boolean enableLogRequest() {
			return Boolean.parseBoolean(getValue(PROP_LOG_REQUEST));
		}

		public String getHost() {
			final String host = getValue(PROP_HOST);
			if ((host == null) || host.isEmpty()) {
				return "0.0.0.0";
			}
			return host;
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

		public int getHeartbeat() {
			int hb = DEFAULT_HEARTBEAT;
			try {
				hb = Integer.parseInt(getValue(PROP_HEARTBEAT));
				if (hb < 0) {
					hb = DEFAULT_HEARTBEAT;
				}
			} catch (Exception ign) {
			}
			return hb;
		}

		public String getKexAlgorithms() {
			final String value = getValue(PROP_KEX_ALGORITHMS);
			if (value == null) {
				return DEFAULT_KEX_ALGORITHMS;
			}
			return value;
		}

		public String getCiphers() {
			final String value = getValue(PROP_CIPHERS);
			if (value == null) {
				return DEFAULT_CIPHERS;
			}
			return value;
		}

		public String getMacs() {
			final String value = getValue(PROP_MACS);
			if (value == null) {
				return DEFAULT_MACS;
			}
			return value;
		}

		public int getMinSizeDHGEX() {
			final String value = getValue(PROP_DHGEX_MIN);
			if (value == null) {
				return DEFAULT_DHGEX_MIN;
			}
			return Integer.parseInt(value);
		}

		public int getMaxSizeDHGEX() {
			final String value = getValue(PROP_DHGEX_MAX);
			if (value == null) {
				return DEFAULT_DHGEX_MAX;
			}
			return Integer.parseInt(value);
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

		public boolean checkUserPassword(final ServerSession session, final String user, final String pwd) {
			final StringBuilder sb = new StringBuilder(40);
			boolean traceInfo = false;
			boolean authOk = false;
			try {
				if (!isEnabledUser(user)) {
					sb.append("[user disabled]");
					return authOk;
				}
				final String value = getValue(user, PROP_PWD);
				if (value == null) {
					sb.append("[no password]");
					return authOk;
				}
				final boolean isCrypted = PasswordEncrypt.isCrypted(value);
				authOk = isCrypted ? PasswordEncrypt.checkPassword(value, pwd) : value.equals(pwd);
				if (!isCrypted) {
					sb.append("[config-unencrypted]");
				}
				traceInfo = isCrypted;
			} finally {
				sb.append("[").append(authOk ? "OK" : "FAIL").append("]");
				if (authOk) {
					logger.authPasswordPostLogin(session, user, (traceInfo ? Level.INFO : Level.WARN), sb.toString());
				} else {
					logger.authPasswordPostLogin(session, user, Level.ERROR, sb.toString());
				}
			}
			return authOk;
		}

		public boolean checkUserPublicKey(final ServerSession session, final String user, final PublicKey key) {
			final String encodedKey = PublicKeyEntry.toString(key);
			final StringBuilder sb = new StringBuilder(40);
			boolean authOk = false;
			try {
				if (!isEnabledUser(user)) {
					sb.append("[user disabled]");
					return authOk;
				}
				for (int i = 1; i < 1024; i++) {
					final String value = getValue(user, PROP_KEY + i);
					if (value == null) {
						if (i == 1)
							sb.append("[no publickey]");
						break;
					} else {
						// Strip comment in keys
						// ssh-rsa AAAAB3NzaC1y...E7uQ== root@host
						final int s1 = value.indexOf(' ', 0);
						final int s2 = value.indexOf(' ', s1 + 1);
						final String ukey = (s2 > s1 ? value.substring(0, s2) : value);
						if (ukey.equals(encodedKey)) {
							if ((s1 > 0) && (s1 < s2)) {
								sb.append("[").append(value.substring(0, s1)).append("]");
							}
							authOk = true;
							break;
						}
					}
				}
			} finally {
				sb.append("[").append(authOk ? "OK" : "FAIL").append("]");
				if (authOk) {
					logger.authPublicKeyPostLogin(session, user, key, Level.INFO, sb.toString());
				} else {
					logger.authPublicKeyPostLogin(session, user, key, Level.ERROR, sb.toString());
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

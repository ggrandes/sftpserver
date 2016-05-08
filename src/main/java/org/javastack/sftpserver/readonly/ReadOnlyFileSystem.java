package org.javastack.sftpserver.readonly;

import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.WatchService;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.spi.FileSystemProvider;
import java.util.Set;

public class ReadOnlyFileSystem extends FileSystem {
	private final FileSystem fs;

	public ReadOnlyFileSystem(final FileSystem fs) {
		this.fs = fs;
	}

	@Override
	public FileSystemProvider provider() {
		return fs.provider();
	}

	@Override
	public void close() throws IOException {
		fs.close();
	}

	@Override
	public boolean isOpen() {
		return fs.isOpen();
	}

	@Override
	public boolean isReadOnly() {
		return true;
	}

	@Override
	public String getSeparator() {
		return fs.getSeparator();
	}

	@Override
	public Iterable<Path> getRootDirectories() {
		return fs.getRootDirectories();
	}

	@Override
	public Iterable<FileStore> getFileStores() {
		return fs.getFileStores();
	}

	@Override
	public Set<String> supportedFileAttributeViews() {
		return fs.supportedFileAttributeViews();
	}

	@Override
	public Path getPath(final String first, final String... more) {
		return fs.getPath(first, more);
	}

	@Override
	public PathMatcher getPathMatcher(final String syntaxAndPattern) {
		return fs.getPathMatcher(syntaxAndPattern);
	}

	@Override
	public UserPrincipalLookupService getUserPrincipalLookupService() {
		return fs.getUserPrincipalLookupService();
	}

	@Override
	public WatchService newWatchService() throws IOException {
		return fs.newWatchService();
	}
}
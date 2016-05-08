package org.javastack.sftpserver.readonly;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.FileSystem;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import org.apache.sshd.common.file.root.RootedFileSystemProvider;

public class ReadOnlyRootedFileSystemProvider extends RootedFileSystemProvider {
	@Override
	protected FileSystem newFileSystem(final Object src, final Path path, final Map<String, ?> env)
			throws IOException {
		return new ReadOnlyFileSystem(super.newFileSystem(src, path, env));
	}

	@Override
	public void checkAccess(final Path path, final AccessMode... modes) throws IOException {
		for (final AccessMode m : modes) {
			if (AccessMode.WRITE.equals(m)) {
				throw new IOException("ReadOnly FileSystem");
			}
		}
		super.checkAccess(path, modes);
	}

	@Override
	public void move(final Path source, final Path target, final CopyOption... options) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public void copy(final Path source, final Path target, final CopyOption... options) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public void delete(final Path path) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public boolean deleteIfExists(final Path path) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public void createDirectory(final Path dir, final FileAttribute<?>... attrs) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public void createSymbolicLink(final Path link, final Path target, final FileAttribute<?>... attrs)
			throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public void createLink(final Path link, final Path existing) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public void setAttribute(final Path path, final String attribute, final Object value,
			final LinkOption... options) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public OutputStream newOutputStream(final Path path, final OpenOption... options) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public AsynchronousFileChannel newAsynchronousFileChannel(final Path path,
			final Set<? extends OpenOption> options, final ExecutorService executor,
			final FileAttribute<?>... attrs) throws IOException {
		for (final OpenOption o : options) {
			if (!StandardOpenOption.READ.equals(o)) {
				throw new IOException("ReadOnly FileSystem");
			}
		}
		final AsynchronousFileChannel chan = super.newAsynchronousFileChannel(path, options, executor, attrs);
		return new ReadOnlyAsynchronousFileChannel(chan);
	}

	@Override
	public SeekableByteChannel newByteChannel(final Path path, final Set<? extends OpenOption> options,
			final FileAttribute<?>... attrs) throws IOException {
		return newFileChannel(path, options, attrs);
	}

	@Override
	public FileChannel newFileChannel(final Path path, final Set<? extends OpenOption> options,
			final FileAttribute<?>... attrs) throws IOException {
		for (final OpenOption o : options) {
			if (!StandardOpenOption.READ.equals(o)) {
				throw new IOException("ReadOnly FileSystem");
			}
		}
		final FileChannel chan = super.newFileChannel(path, options, attrs);
		return new ReadOnlyFileChannel(chan);
	}
}
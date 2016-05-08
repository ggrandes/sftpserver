package org.javastack.sftpserver.readonly;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

public class ReadOnlyFileChannel extends FileChannel {
	private final FileChannel chan;

	public ReadOnlyFileChannel(final FileChannel chan) {
		this.chan = chan;
	}

	@Override
	public int read(final ByteBuffer dst) throws IOException {
		return chan.read(dst);
	}

	@Override
	public long read(final ByteBuffer[] dsts, final int offset, final int length) throws IOException {
		return read(dsts, offset, length);
	}

	@Override
	public int write(final ByteBuffer src) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public long write(final ByteBuffer[] srcs, final int offset, final int length) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public long position() throws IOException {
		return chan.position();
	}

	@Override
	public FileChannel position(final long newPosition) throws IOException {
		return chan.position(newPosition);
	}

	@Override
	public long size() throws IOException {
		return chan.size();
	}

	@Override
	public FileChannel truncate(final long size) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public void force(final boolean metaData) throws IOException {
		chan.force(metaData);
	}

	@Override
	public long transferTo(final long position, final long count, final WritableByteChannel target)
			throws IOException {
		return chan.transferTo(position, count, target);
	}

	@Override
	public long transferFrom(final ReadableByteChannel src, final long position, final long count)
			throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public int read(final ByteBuffer dst, final long position) throws IOException {
		return read(dst, position);
	}

	@Override
	public int write(final ByteBuffer src, final long position) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public MappedByteBuffer map(final MapMode mode, final long position, final long size) throws IOException {
		if (MapMode.READ_WRITE.equals(mode)) {
			throw new IOException("ReadOnly FileSystem");
		}
		return chan.map(mode, position, size);
	}

	@Override
	public FileLock lock(final long position, final long size, final boolean shared) throws IOException {
		return chan.lock(position, size, shared);
	}

	@Override
	public FileLock tryLock(final long position, final long size, final boolean shared) throws IOException {
		return chan.tryLock(position, size, shared);
	}

	@Override
	protected void implCloseChannel() throws IOException {
	}
};

package org.javastack.sftpserver.readonly;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousFileChannel;
import java.nio.channels.CompletionHandler;
import java.nio.channels.FileLock;
import java.util.concurrent.Future;

public class ReadOnlyAsynchronousFileChannel extends AsynchronousFileChannel {
	private final AsynchronousFileChannel chan;

	public ReadOnlyAsynchronousFileChannel(final AsynchronousFileChannel chan) {
		this.chan = chan;
	}

	@Override
	public void close() throws IOException {
		chan.close();
	}

	@Override
	public boolean isOpen() {
		return chan.isOpen();
	}

	@Override
	public long size() throws IOException {
		return chan.size();
	}

	@Override
	public AsynchronousFileChannel truncate(final long size) throws IOException {
		throw new IOException("ReadOnly FileSystem");
	}

	@Override
	public void force(final boolean metaData) throws IOException {
		chan.force(metaData);
	}

	@Override
	public <A> void lock(final long position, final long size, final boolean shared, final A attachment,
			final CompletionHandler<FileLock, ? super A> handler) {
		chan.lock(position, size, shared, attachment, handler);
	}

	@Override
	public Future<FileLock> lock(final long position, final long size, final boolean shared) {
		return chan.lock(position, size, shared);
	}

	@Override
	public FileLock tryLock(final long position, final long size, final boolean shared) throws IOException {
		return chan.tryLock(position, size, shared);
	}

	@Override
	public <A> void read(final ByteBuffer dst, final long position, final A attachment,
			final CompletionHandler<Integer, ? super A> handler) {
		chan.read(dst, position, attachment, handler);
	}

	@Override
	public Future<Integer> read(final ByteBuffer dst, final long position) {
		return chan.read(dst, position);
	}

	@Override
	public <A> void write(final ByteBuffer src, final long position, final A attachment,
			final CompletionHandler<Integer, ? super A> handler) {
		throw new UnsupportedOperationException("ReadOnly FileSystem");
	}

	@Override
	public Future<Integer> write(final ByteBuffer src, final long position) {
		throw new UnsupportedOperationException("ReadOnly FileSystem");
	}
}

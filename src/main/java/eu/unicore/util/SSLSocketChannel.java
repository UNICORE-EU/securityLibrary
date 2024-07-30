/*
 * Copyright 2015 Corey Baswell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 * https://github.com/baswerc/niossl
 */
package eu.unicore.util;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

import java.io.IOException;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketOption;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.Set;
import java.util.concurrent.ExecutorService;

/**
 * A wrapper around a real {@link SocketChannel} that adds SSL support.
 * 
 * NOTE: selection can only be done on the underlying channel - getWrappedSocketChannel()
 */
public class SSLSocketChannel extends SocketChannel
{
	private final SocketChannel socketChannel;

	private final SSLEngineBuffer sslEngineBuffer;

	/**
	 *
	 * @param socketChannel The underlying SocketChannel.
	 * @param sslEngine The SSL engine to use for traffic back and forth on the given SocketChannel.
	 * @param executorService Used to execute long running, blocking SSL operations such as certificate
	 *        validation with a CA (<a href="http://docs.oracle.com/javase/7/docs/api/javax/net/ssl/SSLEngineResult.HandshakeStatus.html#NEED_TASK">NEED_TASK</a>)
	 * @throws IOException
	 */
	public SSLSocketChannel(SocketChannel socketChannel, final SSLEngine sslEngine, ExecutorService executorService)
	{
		super(socketChannel.provider());
		this.socketChannel = socketChannel;
		sslEngineBuffer = new SSLEngineBuffer(socketChannel, sslEngine, executorService);
	}

	public SocketChannel getWrappedSocketChannel()
	{
		return socketChannel;
	}

	/**
	 * <p>Reads a sequence of bytes from this channel into the given buffer.</p>
	 *
	 * <p>An attempt is made to read up to r bytes from the channel, where r is the number of bytes
	 * remaining in the buffer, that is, dst.remaining(), at the moment this method is invoked.</p>
	 *
	 * <p>Suppose that a byte sequence of length n is read, where 0 &lt;= n &lt;= r. This byte sequence
	 * will be transferred into the buffer so that the first byte in the sequence is at index p and the
	 * last byte is at index p + n - 1, where p is the buffer's position at the moment this method is invoked.
	 * Upon return the buffer's position will be equal to p + n; its limit will not have changed.</p>
	 *
	 * <p>A read operation might not fill the buffer, and in fact it might not read any bytes at all.
	 * Whether or not it does so depends upon the nature and state of the channel. A socket channel
	 * in non-blocking mode, for example, cannot read any more bytes than are immediately available
	 * from the socket's input buffer; similarly, a file channel cannot read any more bytes than remain
	 * in the file. It is guaranteed, however, that if a channel is in blocking mode and there is at least
	 * one byte remaining in the buffer then this method will block until at least one byte is read.</p>
	 *
	 * <p>This method may be invoked at any time. If another thread has already initiated a read operation
	 * upon this channel, however, then an invocation of this method will block until the first operation is
	 * complete.</p>
	 *
	 * @param applicationBuffer The buffer into which bytes are to be transferred
	 * @return The number of bytes read, possibly zero, or -1 if the channel has reached end-of-stream
	 * @throws java.nio.channels.NotYetConnectedException If this channel is not yet connected
	 * @throws java.nio.channels.ClosedChannelException If this channel is closed
	 * @throws java.nio.channels.AsynchronousCloseException If another thread closes this channel while the read operation is in progress
	 * @throws java.nio.channels.ClosedByInterruptException If another thread interrupts the current thread while 
	 *         the read operation is in progress, thereby closing the channel and setting the current thread's interrupt status
	 * @throws IOException If some other I/O error occurs
	 * @throws IllegalArgumentException If the given applicationBuffer capacity ({@link ByteBuffer#capacity()} is less
	 *         than the application buffer size of the {@link SSLEngine} session application buffer size
	 *         ({@link SSLSession#getApplicationBufferSize()} this channel was constructed with.
	 */
	@Override
	synchronized public int read(ByteBuffer applicationBuffer) throws IOException, IllegalArgumentException
	{
		int intialPosition = applicationBuffer.position();

		int readFromChannel = sslEngineBuffer.unwrap(applicationBuffer);

		if (readFromChannel < 0)
		{
			return readFromChannel;
		}
		else
		{
			int totalRead = applicationBuffer.position() - intialPosition;
			return totalRead;
		}
	}

	/**
	 * <p>Writes a sequence of bytes to this channel from the given buffer.</p>
	 *
	 * <p>An attempt is made to write up to r bytes to the channel, where r is the number of bytes
	 * remaining in the buffer, that is, src.remaining(), at the moment this method is invoked.</p>
	 *
	 * <p>Suppose that a byte sequence of length n is written, where 0 &lt;= n &lt;= r. This byte sequence
	 * will be transferred from the buffer starting at index p, where p is the buffer's position at
	 * the moment this method is invoked; the index of the last byte written will be p + n - 1. Upon
	 * return the buffer's position will be equal to p + n; its limit will not have changed.</p>
	 *
	 * <p>Unless otherwise specified, a write operation will return only after writing all of the r requested bytes.
	 * Some types of channels, depending upon their state, may write only some of the bytes or possibly none at all.
	 * A socket channel in non-blocking mode, for example, cannot write any more bytes than are free in the socket's
	 * output buffer.</p>
	 *
	 * <p>This method may be invoked at any time. If another thread has already initiated a write operation upon
	 * this channel, however, then an invocation of this method will block until the first operation is complete.</p>
	 *
	 * @param applicationBuffer The buffer from which bytes are to be retrieved
	 * @return The number of bytes written, possibly zero
	 * @throws java.nio.channels.NotYetConnectedException If this channel is not yet connected
	 * @throws java.nio.channels.ClosedChannelException If this channel is closed
	 * @throws java.nio.channels.AsynchronousCloseException If another thread closes this channel while the read operation is in progress
	 * @throws java.nio.channels.ClosedByInterruptException If another thread interrupts the current thread while the read operation
	 *         is in progress, thereby closing the channel and setting the current thread's interrupt status
	 * @throws IOException If some other I/O error occurs
	 * @throws IllegalArgumentException If the given applicationBuffer capacity ({@link ByteBuffer#capacity()} is less than the application
	 *         buffer size of the {@link SSLEngine} session application buffer size ({@link SSLSession#getApplicationBufferSize()} this channel
	 *         was constructed with.
	 */
	@Override
	synchronized public int write(ByteBuffer applicationBuffer) throws IOException, IllegalArgumentException
	{
		int intialPosition = applicationBuffer.position();
		int writtenToChannel = sslEngineBuffer.wrap(applicationBuffer);

		if (writtenToChannel < 0)
		{
			return writtenToChannel;
		}
		else
		{
			int totalWritten = applicationBuffer.position() - intialPosition;
			return totalWritten;
		}
	}


	/**
	 * <p>Reads a sequence of bytes from this channel into a subsequence of the given buffers.</p>
	 *
	 * <p>An invocation of this method attempts to read up to r bytes from this channel, where r is
	 * the total number of bytes remaining the specified subsequence of the given buffer array, that is,
	 * <pre>
	 * {@code
	 * dsts[offset].remaining()
	 *   + dsts[offset+1].remaining()
	 *   + ... + dsts[offset+length-1].remaining()
	 * }
	 * </pre>
	 * <p>at the moment that this method is invoked.</p>
	 *
	 * <p>Suppose that a byte sequence of length n is read, where 0 &lt;= n &lt;= r. Up to the 
	 * first dsts[offset].remaining() bytes of this sequence are transferred into buffer dsts[offset],
	 * up to the next dsts[offset+1].remaining() bytes are transferred into buffer dsts[offset+1],
	 * and so forth, until the entire byte sequence is transferred into the given buffers. As many
	 * bytes as possible are transferred into each buffer, hence the final position of each updated buffer,
	 * except the last updated buffer, is guaranteed to be equal to that buffer's limit.</p>
	 *
	 * <p>This method may be invoked at any time. If another thread has already initiated a read operation
	 * upon this channel, however, then an invocation of this method will block until the first operation
	 * is complete.</p>
	 *
	 * @param applicationByteBuffers The buffers into which bytes are to be transferred
	 * @param offset The offset within the buffer array of the first buffer into which bytes are to be transferred; must be
	 *        non-negative and no larger than dsts.length
	 * @param length The maximum number of buffers to be accessed; must be non-negative and no larger than <code>dsts.length - offset</code>
	 * @return The number of bytes read, possibly zero, or -1 if the channel has reached end-of-stream
	 * @throws java.nio.channels.NotYetConnectedException If this channel is not yet connected
	 * @throws java.nio.channels.ClosedChannelException If this channel is closed
	 * @throws java.nio.channels.AsynchronousCloseException If another thread closes this channel while the read operation is in progress
	 * @throws java.nio.channels.ClosedByInterruptException If another thread interrupts the current thread while the read operation is
	 *         in progress, thereby closing the channel and setting the current thread's interrupt status
	 * @throws IOException If some other I/O error occurs
	 * @throws IllegalArgumentException If one of the given applicationBuffers capacity ({@link ByteBuffer#capacity()} is less than
	 *         the application buffer size of the {@link SSLEngine} session application buffer size ({@link SSLSession#getApplicationBufferSize()}
	 *         this channel was constructed was.
	 */
	@Override
	public long read(ByteBuffer[] applicationByteBuffers, int offset, int length) throws IOException, IllegalArgumentException
	{
		long totalRead = 0;
		for (int i = offset; i < length; i++)
		{
			ByteBuffer applicationByteBuffer = applicationByteBuffers[i];
			if (applicationByteBuffer.hasRemaining())
			{
				int read = read(applicationByteBuffer);
				if (read > 0)
				{
					totalRead += read;
					if (applicationByteBuffer.hasRemaining())
					{
						break;
					}
				}
				else
				{
					if ((read < 0) && (totalRead == 0))
					{
						totalRead = -1;
					}
					break;
				}
			}
		}
		return totalRead;
	}

	/**
	 * <p>Writes a sequence of bytes to this channel from a subsequence of the given buffers.</p>
	 *
	 * <p>An attempt is made to write up to r bytes to this channel, where r is the total number of bytes remaining in the specified subsequence of the given buffer array, that is,</p>
	 * <pre>
	 * {@code
	 * srcs[offset].remaining()
	 *   + srcs[offset+1].remaining()
	 *   + ... + srcs[offset+length-1].remaining()
	 * }
	 * </pre>
	 * <p>at the moment that this method is invoked.</p>
	 *
	 * <p>Suppose that a byte sequence of length n is written, where 0 &lt;= n &lt;= r. Up to the first srcs[offset].remaining() bytes
	 * of this sequence are written from buffer srcs[offset], up to the next srcs[offset+1].remaining() bytes are written from
	 * buffer srcs[offset+1], and so forth, until the entire byte sequence is written. As many bytes as possible are written from each buffer,
	 * hence the final position of each updated buffer, except the last updated buffer, is guaranteed to be equal to that buffer's limit.</p>
	 *
	 * <p>Unless otherwise specified, a write operation will return only after writing all of the r requested bytes. Some types of channels,
	 * depending upon their state, may write only some of the bytes or possibly none at all. A socket channel in non-blocking mode, for example,
	 * cannot write any more bytes than are free in the socket's output buffer.</p>
	 *
	 * <p>This method may be invoked at any time. If another thread has already initiated a write operation upon this channel, however, then an
	 * invocation of this method will block until the first operation is complete.</p>
	 *
	 * @param applicationByteBuffers The buffers from which bytes are to be retrieved
	 * @param offset offset - The offset within the buffer array of the first buffer from which bytes are to be retrieved; must be non-negative 
	 *        and no larger than <code>srcs.length</code>
	 * @param length The maximum number of buffers to be accessed; must be non-negative and no larger than <code>srcs.length - offset</code>
	 * @return The number of bytes written, possibly zero
	 * @throws java.nio.channels.NotYetConnectedException If this channel is not yet connected
	 * @throws java.nio.channels.ClosedChannelException If this channel is closed
	 * @throws java.nio.channels.AsynchronousCloseException If another thread closes this channel while the read operation is in progress
	 * @throws java.nio.channels.ClosedByInterruptException If another thread interrupts the current thread while the read operation is in
	 *         progress, thereby closing the channel and setting the current thread's interrupt status
	 * @throws IOException If some other I/O error occurs
	 * @throws IllegalArgumentException If one of the given applicationBuffers capacity ({@link ByteBuffer#capacity()} is less than the
	 *         application buffer size of the {@link SSLEngine} session application buffer size ({@link SSLSession#getApplicationBufferSize()}
	 *         this channel was constructed was.
	 */
	@Override
	public long write(ByteBuffer[] applicationByteBuffers, int offset, int length) throws IOException, IllegalArgumentException
	{
		long totalWritten = 0;
		for (int i = offset; i < length; i++)
		{
			ByteBuffer byteBuffer = applicationByteBuffers[i];
			if (byteBuffer.hasRemaining())
			{
				int written = write(byteBuffer);
				if (written > 0)
				{
					totalWritten += written;
					if (byteBuffer.hasRemaining())
					{
						break;
					}
				}
				else
				{
					if ((written < 0) && (totalWritten == 0))
					{
						totalWritten = -1;
					}
					break;
				}
			}
		}
		return totalWritten;
	}

	@Override
	public Socket socket ()
	{
		return socketChannel.socket();
	}

	@Override
	public boolean isConnected ()
	{
		return socketChannel.isConnected();
	}

	@Override
	public boolean isConnectionPending ()
	{
		return socketChannel.isConnectionPending();
	}

	@Override
	public boolean connect (SocketAddress socketAddress)throws IOException
	{
		return socketChannel.connect(socketAddress);
	}

	@Override
	public boolean finishConnect ()throws IOException
	{
		return socketChannel.finishConnect();
	}

	@Override
	public SocketChannel bind(SocketAddress local) throws IOException
	{
		socketChannel.bind(local);
		return this;
	}

	@Override
	public SocketAddress getLocalAddress() throws IOException
	{
		return socketChannel.getLocalAddress();
	}

	@Override
	public <T> SocketChannel setOption(SocketOption<T> name, T value) throws IOException
	{
		return socketChannel.setOption(name, value);
	}

	@Override
	public <T> T getOption(SocketOption<T> name) throws IOException
	{
		return socketChannel.getOption(name);
	}

	@Override
	public Set<SocketOption<?>> supportedOptions()
	{
		return socketChannel.supportedOptions();
	}

	@Override
	public SocketChannel shutdownInput() throws IOException
	{
		return socketChannel.shutdownInput();
	}

	@Override
	public SocketChannel shutdownOutput() throws IOException
	{
		return socketChannel.shutdownOutput();
	}

	@Override
	public SocketAddress getRemoteAddress() throws IOException
	{
		return socketChannel.getRemoteAddress();
	}

	@Override
	protected void implConfigureBlocking (boolean b)throws IOException
	{
		socketChannel.configureBlocking(b);
	}

	@Override
	protected void implCloseSelectableChannel ()throws IOException
	{
		try
		{
			sslEngineBuffer.flushNetworkOutbound();
		}
		catch (Exception e)
		{}

		socketChannel.close();
		sslEngineBuffer.close();
	}

	public static class SSLEngineBuffer
	{

		private final SocketChannel socketChannel;

		private final SSLEngine sslEngine;

		private final ExecutorService executorService;

		private final ByteBuffer networkInboundBuffer;

		private final ByteBuffer networkOutboundBuffer;

		private final int minimumApplicationBufferSize;

		private final ByteBuffer unwrapBuffer;

		private final ByteBuffer wrapBuffer;

		public SSLEngineBuffer(SocketChannel socketChannel, SSLEngine sslEngine, ExecutorService executorService)
		{
			this.socketChannel = socketChannel;
			this.sslEngine = sslEngine;
			this.executorService = executorService;

			SSLSession session = sslEngine.getSession();
			int networkBufferSize = session.getPacketBufferSize();

			networkInboundBuffer = ByteBuffer.allocate(networkBufferSize);

			networkOutboundBuffer = ByteBuffer.allocate(networkBufferSize);
			networkOutboundBuffer.flip();


			minimumApplicationBufferSize = session.getApplicationBufferSize();
			unwrapBuffer = ByteBuffer.allocate(minimumApplicationBufferSize);
			wrapBuffer = ByteBuffer.allocate(minimumApplicationBufferSize);
			wrapBuffer.flip();
		}

		int unwrap(ByteBuffer applicationInputBuffer) throws IOException
		{
			if (applicationInputBuffer.capacity() < minimumApplicationBufferSize)
			{
				throw new IllegalArgumentException("Application buffer size must be at least: " + minimumApplicationBufferSize);
			}

			if (unwrapBuffer.position() != 0)
			{
				unwrapBuffer.flip();
				while (unwrapBuffer.hasRemaining() && applicationInputBuffer.hasRemaining())
				{
					applicationInputBuffer.put(unwrapBuffer.get());
				}
				unwrapBuffer.compact();
			}

			int totalUnwrapped = 0;
			int unwrapped, wrapped;

			do
			{
				totalUnwrapped += unwrapped = doUnwrap(applicationInputBuffer);
				wrapped = doWrap(wrapBuffer);
			}
			while (unwrapped > 0 || wrapped > 0 && (networkOutboundBuffer.hasRemaining() && networkInboundBuffer.hasRemaining()));

			return totalUnwrapped;
		}

		int wrap(ByteBuffer applicationOutboundBuffer) throws IOException
		{
			int wrapped = doWrap(applicationOutboundBuffer);
			doUnwrap(unwrapBuffer);
			return wrapped;
		}

		int flushNetworkOutbound() throws IOException
		{
			return send(socketChannel, networkOutboundBuffer);
		}

		int send(SocketChannel channel, ByteBuffer buffer) throws IOException
		{
			int totalWritten = 0;
			while (buffer.hasRemaining())
			{
				int written = channel.write(buffer);

				if (written == 0)
				{
					break;
				}
				else if (written < 0)
				{
					return (totalWritten == 0) ? written : totalWritten;
				}
				totalWritten += written;
			}
			return totalWritten;
		}

		void close()
		{
			try
			{
				sslEngine.closeInbound();
			}
			catch (Exception e)
			{}

			try
			{
				sslEngine.closeOutbound();
			}
			catch (Exception e)
			{}
		}

		private int doUnwrap(ByteBuffer applicationInputBuffer) throws IOException
		{
			int totalReadFromChannel = 0;

			// Keep looping until peer has no more data ready or the applicationInboundBuffer is full
			UNWRAP: do
			{
				// 1. Pull data from peer into networkInboundBuffer

				int readFromChannel = 0;
				while (networkInboundBuffer.hasRemaining())
				{
					int read = socketChannel.read(networkInboundBuffer);
					if (read <= 0)
					{
						if ((read < 0) && (readFromChannel == 0) && (totalReadFromChannel == 0))
						{
							// No work done and we've reached the end of the channel from peer
							return read;
						}
						break;
					}
					else
					{
						readFromChannel += read;
					}
				}


				networkInboundBuffer.flip();
				if (!networkInboundBuffer.hasRemaining())
				{
					networkInboundBuffer.compact();
					return totalReadFromChannel;
				}

				totalReadFromChannel += readFromChannel;

				try
				{
					SSLEngineResult result = sslEngine.unwrap(networkInboundBuffer, applicationInputBuffer);

					switch (result.getStatus())
					{
					case OK:
						SSLEngineResult.HandshakeStatus handshakeStatus = result.getHandshakeStatus();
						switch (handshakeStatus)
						{
						case NEED_UNWRAP:
							break;

						case NEED_WRAP:
							break UNWRAP;

						case NEED_TASK:
							runHandshakeTasks();
							break;

						case NOT_HANDSHAKING:
						default:
							break;
						}
						break;

					case BUFFER_OVERFLOW:
						break UNWRAP;

					case CLOSED:
						return totalReadFromChannel == 0 ? -1 : totalReadFromChannel;

					case BUFFER_UNDERFLOW:
						break;
					}
				}
				finally
				{
					networkInboundBuffer.compact();
				}
			}
			while (applicationInputBuffer.hasRemaining());

			return totalReadFromChannel;
		}

		private int doWrap(ByteBuffer applicationOutboundBuffer) throws IOException
		{
			int totalWritten = 0;

			// 1. Send any data already wrapped out channel

			if (networkOutboundBuffer.hasRemaining())
			{
				totalWritten = send(socketChannel, networkOutboundBuffer);
				if (totalWritten < 0)
				{
					return totalWritten;
				}
			}

			// 2. Any data in application buffer ? Wrap that and send it to peer.

			WRAP: while (true)
			{
				networkOutboundBuffer.compact();
				SSLEngineResult result = sslEngine.wrap(applicationOutboundBuffer, networkOutboundBuffer);

				networkOutboundBuffer.flip();
				if (networkOutboundBuffer.hasRemaining())
				{
					int written = send(socketChannel, networkOutboundBuffer);
					if (written < 0)
					{
						return totalWritten == 0 ? written : totalWritten;
					}
					else
					{
						totalWritten += written;
					}
				}

				switch (result.getStatus())
				{
				case OK:
					switch (result.getHandshakeStatus())
					{
					case NEED_WRAP:
						break;

					case NEED_UNWRAP:
						break WRAP;

					case NEED_TASK:
						runHandshakeTasks();
						break;

					case NOT_HANDSHAKING:
						if (applicationOutboundBuffer.hasRemaining())
						{
							break;
						}
						else
						{
							break WRAP;
						}

					default:
						break;
					}

					break;

				case BUFFER_OVERFLOW:
					break WRAP;

				case CLOSED:
					break WRAP;

				case BUFFER_UNDERFLOW:
					break WRAP;
				}
			}

			return totalWritten;
		}

		private void runHandshakeTasks ()
		{
			while (true)
			{
				final Runnable runnable = sslEngine.getDelegatedTask();
				if (runnable == null)
				{
					break;
				}
				else
				{
					if(executorService!=null) {
						executorService.execute(runnable);
					}else {
						runnable.run();
					}
				}
			}
		}
	}
}

package eu.unicore.util.jetty.forwarding;

import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.concurrent.Executor;

import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.Logger;
import org.eclipse.jetty.io.AbstractConnection;
import org.eclipse.jetty.io.Connection;
import org.eclipse.jetty.io.EndPoint;

import eu.unicore.util.ChannelUtils;
import eu.unicore.util.Log;

/**
 * Minimalistic implementation of {@link org.eclipse.jetty.io.Connection}
 * that forwards client data to the backend
 *
 * @author schuller
 */
public class ForwardingConnection extends AbstractConnection implements Connection.UpgradeTo
{
	private static final Logger LOG = Log.getLogger(Log.HTTP_SERVER, ForwardingConnection.class);

	private final ByteBuffer buffer;
	
	private final SocketChannel backend;
	
	public ForwardingConnection(EndPoint endPoint, Executor executor, SocketChannel backend, int buffersize)
	{
		super(endPoint, executor);
		endPoint.setIdleTimeout(-1);
		this.backend = backend;
		buffer = ByteBuffer.allocate(65536);
	}
	
	public ForwardingConnection(EndPoint endPoint, Executor executor, SocketChannel backend)
	{
		this(endPoint, executor, backend, 65536);
	}
	
	public SocketChannel getBackend() {
		return backend;
	}

	@Override
	public void onUpgradeTo(ByteBuffer buffer) {
		LOG.debug("**** onUpgrade with {} bytes ", buffer.position());
		// should not have any payload here
		assert buffer.position()==0;
	}

	@Override
	public void onFillable() {
		try {
			buffer.clear();
			buffer.limit(0);
			int n = getEndPoint().fill(buffer);
			if(n==-1) {
				LOG.debug("Client shutdown, closing.");
				close();
			}
			else {
				if(n>0) {
					int written = ChannelUtils.writeFully(backend, buffer);
					LOG.debug("<-- {} bytes from client --> {} to backend", n, written);
				}
			fillInterested();
			}
		}catch(Exception ioe) {
			Log.logException("Error handling forwarding to backend "+backend, ioe, LOG);
			this.close();
		}
	}

	@Override
	public void close() {
		IOUtils.closeQuietly(backend);
		super.close();
	}

	@Override
	public void onOpen() {
		LOG.debug("onOpen");
		super.onOpen();
		fillInterested();
	}
}

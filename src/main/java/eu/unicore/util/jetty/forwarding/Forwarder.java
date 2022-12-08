package eu.unicore.util.jetty.forwarding;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.Logger;
import org.eclipse.jetty.util.Callback;

import eu.unicore.util.Log;
import eu.unicore.util.SSLSocketChannel;

/**
 * Handles the backend-to-client part for all running forwarding connections
 *
 * @author schuller
 */
public class Forwarder implements Runnable {

	private static final Logger log = Log.getLogger(Log.HTTP_SERVER, Forwarder.class);

	private final Selector selector;

	private final List<SelectionKey> keys = new ArrayList<>();

	private final ByteBuffer buffer;

	private static Forwarder _instance;

	public static int DEFAULT_BUFFER_SIZE = 65536;

	public static synchronized Forwarder get() throws IOException {
		if(_instance==null) {
			_instance = new Forwarder(DEFAULT_BUFFER_SIZE);
			new Thread(_instance, "Forwarder").start();
		}
		return _instance;
	}

	protected Forwarder(int bufferSize) throws IOException {
		buffer = ByteBuffer.allocate(bufferSize);
		selector = Selector.open();
	}

	/**
	 * add a new ForwardingConnection
	 *
	 * @param forwardingConnection
	 * @throws IOException
	 */
	public synchronized void attach(final ForwardingConnection forwardingConnection) 
			throws IOException {
		assert forwardingConnection!=null : "Client connection cannot be null";
		SocketChannel backend = forwardingConnection.getBackend();
		backend.configureBlocking(false);
		SocketChannel selectable = backend instanceof SSLSocketChannel ?
				((SSLSocketChannel)backend).getWrappedSocketChannel():
					backend;
				SelectionKey key  = selectable.register(selector,
						SelectionKey.OP_READ,
						forwardingConnection);
				keys.add(key);
				log.info("New forwarding connection to {} started.", backend.getRemoteAddress());
	}

	public void run() {
		try{
			log.info("TCP port forwarder starting.");
			while(true) {
				selector.select(50);
				Iterator<SelectionKey> iter = selector.selectedKeys().iterator();
				while(iter.hasNext()) {
					SelectionKey key = iter.next();
					iter.remove();
					if(key.isValid())dataAvailable(key);
				}
			}
		}catch(Exception ex) {
			log.error(ex);
		}
	}

	public synchronized void dataAvailable(SelectionKey key) {
		ForwardingConnection toClient = (ForwardingConnection)key.attachment();
		SocketChannel backend = toClient.getBackend();
		try{
			buffer.clear();
			int n = backend.read(buffer);
			if(n>0) {
				buffer.flip();
				toClient.getEndPoint().write(Callback.NOOP, buffer);
				log.debug("Wrote {} bytes from backend to client.", n);
			}
			if(n==-1) {
				log.debug("Backend at EOF, closing.", n);
				IOUtils.closeQuietly(toClient);
				key.cancel();
			}
		}catch(IOException ioe) {
			log.error(ioe);
			IOUtils.closeQuietly(toClient);
			key.cancel();
		}
	}

}

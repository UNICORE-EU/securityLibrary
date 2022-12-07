package eu.unicore.util.jetty.forwarding;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.ArrayList;
import java.util.List;

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
				selector.selectedKeys().forEach(key -> dataAvailable(key));
			}
		}catch(Exception ex) {
			log.error(ex);
		}
	}


	public synchronized void dataAvailable(SelectionKey key) {
		ForwardingConnection toClient = (ForwardingConnection)key.attachment();
		SocketChannel vsite = toClient.getBackend();
		try{
			if(key.isReadable()) {
				buffer.clear();
				int n = vsite.read(buffer);
				if(n>0) {
					buffer.flip();
					toClient.getEndPoint().write(Callback.NOOP, buffer);
					log.debug("Wrote {} bytes from vsite to client.", n);
				}
			}
		}catch(IOException ioe) {
			log.error(ioe);
		}
	}

}

package eu.unicore.util.jetty;

import org.eclipse.jetty.server.ConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;

/**
 * Extension of the Jetty {@link ServerConnector} logging the address of the remote host trying to 
 * establish a connection.
 * @author golbi
 */
public class PlainServerConnector extends ServerConnector {
	
	public PlainServerConnector(Server server, ConnectionFactory... factories)
	{
		super(server, factories);
	}

}

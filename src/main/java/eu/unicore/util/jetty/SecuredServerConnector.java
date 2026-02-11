package eu.unicore.util.jetty;

import org.apache.logging.log4j.Logger;
import org.eclipse.jetty.server.ConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.unicore.util.Log;

/**
 * Extension of the Jetty {@link ServerConnector} logging the address of the remote host trying to 
 * establish a connection. Additionally provides a method to retrieve {@link SslContextFactory} set for the connector.
 * 
 * @author schuller
 * @author golbi
 */
public class SecuredServerConnector extends ServerConnector {
	
	private final static Logger log = Log.getLogger(Log.CONNECTIONS, SecuredServerConnector.class);
	private SslContextFactory.Server sslContextFactory;
	
	public SecuredServerConnector(Server server, SslContextFactory.Server sslContextFactory, 
			ConnectionFactory... factories)
	{
		super(server, sslContextFactory, factories);
		this.sslContextFactory = sslContextFactory;
	}

	public SslContextFactory.Server getSslContextFactory()
	{
		return sslContextFactory;
	}
	
	public static SslContextFactory.Server createContextFactory(X509CertChainValidator validator, 
			X509Credential credential) throws Exception
	{
		return JettyConnectorUtils.createJettyContextFactory(validator, credential, log);
	}
}

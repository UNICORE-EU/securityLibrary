package eu.unicore.security.util.client;


import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.FormatMode;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator;
import eu.unicore.security.util.Log;
import eu.unicore.security.util.LoggingX509TrustManager;


/**
 * Some (small) parts of this class can ramain from the code from Commons 
 * HTTPClient "contrib" section, by Oleg Kalnichevski<br/>
 * 
 * 
 * <p>
 * AuthSSLProtocolSocketFactory validate the identity of the HTTPS server 
 * using a provided {@link X509CertChainValidator}, can present {@link X509Credential} 
 * to authenticate the client and install a standard 
 * </p>
 * 
 * @author <a href="mailto:oleg -at- ural.ru">Oleg Kalnichevski</a>
 * @author K. Benedyczak
 * </p>
 */

public class AuthSSLProtocolSocketFactory implements SecureProtocolSocketFactory
{
	private static final Logger log = Log.getLogger(Log.SECURITY,
			AuthSSLProtocolSocketFactory.class);

	private SSLContext sslcontext = null;
	private IClientConfiguration sec;

	public AuthSSLProtocolSocketFactory(IClientConfiguration sec)
	{
		this.sec = sec;
	}

	private synchronized SSLContext createSSLContext()
	{
		try
		{
			KeyManager km;
			if (sec.doSSLAuthn())
			{
				km = sec.getCredential().getKeyManager();
				if (log.isTraceEnabled())
					debugKS(sec.getCredential());
			} else
			{
				km = new NoAuthKeyManager();
				log.trace("Not authenticating client");
			}
			
			X509TrustManager tm = SocketFactoryCreator.getSSLTrustManager(sec.getValidator());
			tm = new LoggingX509TrustManager(tm);
			if (log.isTraceEnabled())
				debugTS(sec.getValidator());
			
			SSLContext sslcontext = SSLContext.getInstance("TLS");
			sslcontext.init(new KeyManager[] {km}, new TrustManager[] {tm}, null);
			
			return sslcontext;
		} catch (Exception e)
		{
			log.fatal(e.getMessage(), e);
			throw new RuntimeException(e);
		}
	}

	private void debugTS(X509CertChainValidator validator)
	{
		X509Certificate trustedCerts[] = validator.getTrustedIssuers();
		for (X509Certificate cert: trustedCerts)
		{
			log.trace("Currently(!) trusted certificate:\n" + 
					CertificateUtils.format(cert, FormatMode.FULL));
		}
	}
	
	private void debugKS(X509Credential c)
	{
		X509Certificate[] certs = c.getCertificateChain();
		X509Certificate[] certs509 = CertificateUtils.convertToX509Chain(certs);
		log.trace("Client's certificate chain:" + 
				CertificateUtils.format(certs509, FormatMode.FULL));
	}	
	
	private SSLContext getSSLContext()
	{
		if (this.sslcontext == null)
		{
			this.sslcontext = createSSLContext();
		}
		return this.sslcontext;
	}

	/**
	 * Attempts to get a new socket connection to the given host within the
	 * given time limit.
	 * <p>
	 * To circumvent the limitations of older JREs that do not support
	 * connect timeout a controller thread is executed. The controller
	 * thread attempts to create a new socket within the given limit of
	 * time. If socket constructor does not return until the timeout
	 * expires, the controller terminates and throws an
	 * {@link ConnectTimeoutException}
	 * </p>
	 * 
	 * @param host
	 *                the host name/IP
	 * @param port
	 *                the port on the host
	 * @param localAddress
	 *                the local host name/IP to bind the socket to
	 * @param localPort
	 *                the port on the local machine
	 * @param params
	 *                {@link HttpConnectionParams Http connection parameters}
	 * 
	 * @return Socket a new socket
	 * 
	 * @throws IOException
	 *                 if an I/O error occurs while creating the socket
	 * @throws UnknownHostException
	 *                 if the IP address of the host cannot be determined
	 */
	public Socket createSocket(final String host, final int port,
			final InetAddress localAddress, final int localPort,
			final HttpConnectionParams params) throws IOException,
			UnknownHostException, ConnectTimeoutException
	{
		if (params == null)
		{
			throw new IllegalArgumentException(
					"Parameters may not be null");
		}
		int timeout = params.getConnectionTimeout();
		SSLSocketFactory socketfactory = getSSLContext()
				.getSocketFactory();
		if (timeout == 0)
		{
			Socket socket = socketfactory.createSocket(host, port,
					localAddress, localPort); 
			addListeners(socket);
			return socket;
		} else
		{
			Socket socket = socketfactory.createSocket();
			SocketAddress localaddr = new InetSocketAddress(
					localAddress, localPort);
			SocketAddress remoteaddr = new InetSocketAddress(host,
					port);
			socket.bind(localaddr);
			socket.connect(remoteaddr, timeout);
			addListeners(socket);
			return socket;
		}
	}

	private void addListeners(Socket socket)
	{
		((SSLSocket)socket).addHandshakeCompletedListener(new HostnameToCertificateChecker(
				sec.getServerHostnameCheckingMode()));
	}
	
	/**
	 * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int,java.net.InetAddress,int)
	 */
	public Socket createSocket(String host, int port,
			InetAddress clientHost, int clientPort)
			throws IOException, UnknownHostException
	{
		Socket socket = getSSLContext().getSocketFactory().createSocket(host, 
				port, clientHost, clientPort);
		addListeners(socket);
		return socket;
	}

	/**
	 * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int)
	 */
	public Socket createSocket(String host, int port) throws IOException,
			UnknownHostException
	{
		Socket socket = getSSLContext().getSocketFactory().createSocket(host,
				port);
		addListeners(socket);
		return socket;
	}

	/**
	 * @see SecureProtocolSocketFactory#createSocket(java.net.Socket,java.lang.String,int,boolean)
	 */
	public Socket createSocket(Socket socket, String host, int port,
			boolean autoClose) throws IOException,
			UnknownHostException
	{
		Socket socket2 = getSSLContext().getSocketFactory().createSocket(socket,
				host, port, autoClose);
		addListeners(socket2);		
		return socket2;
	}
}

/*
 * Copyright (c) 2014 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.httpclient;

import java.io.IOException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;

/**
 * HTTP Client bug workaround. The SSL socket, before the startHandshake is called has no timeout set
 * as it is configured for the client. Therefore if the server fails to respond the client can hang.
 * What's more the startHandshake() which is now used to init the connection of the HTTP client hides some
 * problems. Therefore we call socket.getSession() and then check the certificates. This is the previous 
 * version of HTTP client way of life, however it was not checking the certs.   
 * @author K. Benedyczak
 */
public class CustomSSLConnectionSocketFactory extends SSLConnectionSocketFactory
{
	private int connectionTimeout;
	
	public CustomSSLConnectionSocketFactory(SSLContext sslContext,
			X509HostnameVerifier hostnameVerifier, int connectionTimeout)
	{
		super(sslContext, hostnameVerifier);
		this.connectionTimeout = connectionTimeout;
	}

	protected void prepareSocket(final SSLSocket socket) throws IOException
	{
		socket.setSoTimeout(connectionTimeout);
		SSLSession session = socket.getSession();
		session.getPeerCertificates();
	}

}

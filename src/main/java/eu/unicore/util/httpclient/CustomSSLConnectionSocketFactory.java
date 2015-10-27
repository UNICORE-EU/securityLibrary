/*
 * Copyright (c) 2014 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.httpclient;

import java.io.IOException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;

/**
 * Configure the SSL socket as soon as the TCP connection has been established.
 * This can include setting timeouts, or customizing the cipher suites and protocols.
 * 
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
		socket.setEnabledProtocols(new String[]{"TLSv1.2"});
		socket.setSoTimeout(connectionTimeout);
	}

}

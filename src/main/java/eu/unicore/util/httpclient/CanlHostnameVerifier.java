/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.httpclient;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.apache.http.conn.ssl.X509HostnameVerifier;

import eu.emi.security.authn.x509.impl.SocketFactoryCreator;

/**
 * Wiring of CANL hostname verification into Apache HTTP client.
 * 
 * Note: this implementation is fairly incomplete. The API is awkward as it forces the 
 * shape of implementation which is no go for us.
 * @author K. Benedyczak
 */
public class CanlHostnameVerifier implements X509HostnameVerifier
{
	private ServerHostnameCheckingMode mode;
	
	public CanlHostnameVerifier(ServerHostnameCheckingMode mode)
	{
		this.mode = mode;
	}

	@Override
	public void verify(String host, SSLSocket ssl) throws IOException
	{
		HostnameMismatchCallbackImpl callback = new HostnameMismatchCallbackImpl(mode);
		SocketFactoryCreator.connectWithHostnameChecking(ssl, callback);
	}
	
	@Override
	public boolean verify(String hostname, SSLSession session)
	{
		throw new RuntimeException("This method is not implemented. Use verify(String, SSLSocket)");
	}

	@Override
	public void verify(String host, X509Certificate cert) throws SSLException
	{
		throw new RuntimeException("This method is not implemented. Use verify(String, SSLSocket)");
	}

	@Override
	public void verify(String host, String[] cns, String[] subjectAlts) throws SSLException
	{
		throw new RuntimeException("This method is not implemented. Use verify(String, SSLSocket)");
	}
}

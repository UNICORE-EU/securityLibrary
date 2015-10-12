/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.httpclient;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import eu.emi.security.authn.x509.helpers.ssl.HostnameToCertificateChecker;

/**
 * Wiring of CANL hostname verification into Apache HTTP client.
 * 
 * @author K. Benedyczak
 */
public class CanlHostnameVerifier implements HostnameVerifier
{
	private ServerHostnameCheckingMode mode;
	
	public CanlHostnameVerifier(ServerHostnameCheckingMode mode)
	{
		this.mode = mode;
	}

	@Override
	public boolean verify(String hostname, SSLSession session)
	{
		HostnameMismatchCallbackImpl callback = new HostnameMismatchCallbackImpl(mode);
		return connectWithHostnameChecking(session, callback);
	}
	
	
	private static boolean connectWithHostnameChecking(SSLSession session, HostnameMismatchCallbackImpl callback) 
	{
		HostnameToCertificateChecker checker = new HostnameToCertificateChecker();
		
		X509Certificate cert;
		Certificate[] serverChain;
		try
		{
			serverChain = session.getPeerCertificates();
		} catch (SSLPeerUnverifiedException e1)
		{
			throw new IllegalStateException("Can't check peer's address as "
					+ "peer's certificate is not available", e1);
		}
		if (serverChain == null || serverChain.length == 0)
			throw new IllegalStateException("JDK BUG? Got null or empty peer certificate array");
		if (!(serverChain[0] instanceof X509Certificate))
			throw new ClassCastException("Peer certificate should be " +
					"an X.509 certificate, but is " + serverChain[0].getClass().getName());
		cert = (X509Certificate) serverChain[0];

		String hostname = session.getPeerHost();
		try
		{
			if (!checker.checkMatching(hostname, cert))
				return callback.nameMismatch(session, cert, hostname);
			else
				return true;
		} catch (Exception e)
		{
			throw new IllegalStateException("Can't check peer's address against its certificate", e);
		}
	}

}

/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.client;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;

import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.impl.HostnameMismatchCallback;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.util.Log;

/**
 * Depending on the configured mode either log problems or log problems and close connections. 
 * @author K. Benedyczak
 */
public class HostnameMismatchCallbackImpl implements HostnameMismatchCallback
{
	private static final Logger log = Log.getLogger(Log.SECURITY, HostnameMismatchCallbackImpl.class);
	
	private ServerHostnameCheckingMode mode;
	
	public HostnameMismatchCallbackImpl(ServerHostnameCheckingMode mode) 
	{
		this.mode = mode;
	}
	
	@Override
	public void nameMismatch(SSLSocket socket, X509Certificate peerCertificate, String hostName)
			throws SSLException
	{
		if (mode == ServerHostnameCheckingMode.NONE)
			return;
		String message = "The server hostname is not matching its certificate subject. This might mean that" +
				" somebody is trying to perform a man-in-the-middle attack by pretending to be" +
				" the server you are trying to connect to. However it is also possible that" +
				" the server uses a certificate which was not associated with its address." +
				" The server DNS name is: '" + hostName + "' and its certificate subject is: '" +
				X500NameUtils.getReadableForm(peerCertificate.getSubjectX500Principal()) + "'.";
		if (mode == ServerHostnameCheckingMode.WARN)
		{
			log.warn(message);
			return;
		}
		
		log.error(message);
		log.error("Closing the connection.");
		try
		{
			socket.close();
		} catch (IOException e)
		{
			log.error("Problem closing socket: " + e.toString(), e);
			throw new RuntimeException(e);
		}
	}
}

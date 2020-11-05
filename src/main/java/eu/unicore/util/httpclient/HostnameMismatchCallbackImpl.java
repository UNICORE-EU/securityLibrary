/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.httpclient;

import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

import org.apache.logging.log4j.Logger;

import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.util.Log;

/**
 * Depending on the configured mode either log problems or log problems and close connections. 
 * @author K. Benedyczak
 */
public class HostnameMismatchCallbackImpl
{
	private static final Logger log = Log.getLogger(Log.SECURITY, HostnameMismatchCallbackImpl.class);
	
	private ServerHostnameCheckingMode mode;
	
	public HostnameMismatchCallbackImpl(ServerHostnameCheckingMode mode) 
	{
		this.mode = mode;
	}
	
	public boolean nameMismatch(SSLSession session, X509Certificate peerCertificate, String hostName)
			throws SSLException
	{
		if (mode == ServerHostnameCheckingMode.NONE)
			return true;
		String message = "The server hostname is not matching its certificate subject. This might mean that" +
				" somebody is trying to perform a man-in-the-middle attack by pretending to be" +
				" the server you are trying to connect to. However it is also possible that" +
				" the server uses a certificate which was not associated with its address." +
				" The server DNS name is: '" + hostName + "' and its certificate subject is: '" +
				X500NameUtils.getReadableForm(peerCertificate.getSubjectX500Principal()) + "'.";
		if (mode == ServerHostnameCheckingMode.WARN)
		{
			log.warn(message);
			return true;
		}
		
		log.error(message);
		log.error("Invalidating connection.");
		session.invalidate();
		return false;
	}
}

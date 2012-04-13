/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.client;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HandshakeCompletedEvent;

import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.impl.AbstractHostnameToCertificateChecker;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.security.util.Log;

/**
 * Depending on the configured mode either log problems or log problems and close connections. 
 * @author K. Benedyczak
 */
public class HostnameToCertificateChecker extends AbstractHostnameToCertificateChecker
{
	private static final Logger log = Log.getLogger(Log.SECURITY, HostnameToCertificateChecker.class);
	
	private ServerHostnameCheckingMode mode;
	
	public HostnameToCertificateChecker(ServerHostnameCheckingMode mode) 
	{
		this.mode = mode;
	}
	
	@Override
	protected void nameMismatch(HandshakeCompletedEvent hce, X509Certificate peerCertificate,
			String hostName)
	{
		if (mode == ServerHostnameCheckingMode.NONE)
			return;
		String message = "The server hostname is not matching its certificate subject. This might mean that" +
				" somebody is trying to perform a man-in-the-middle attack by pretending to be" +
				" the server you are trying to connect to. However it is also possible that" +
				" the server uses a certificate which was not associated with its address." +
				" The server DNS name is: '" + hostName + "' and its certificate subject is: '" +
				X500NameUtils.getReadableForm(peerCertificate.getSubjectX500Principal()) + "'.";
		if (mode == ServerHostnameCheckingMode.CHECK_WARN)
		{
			log.warn(message);
			return;
		}
		
		log.error(message);
		log.error("Closing the connection.");
		try
		{
			hce.getSocket().close();
		} catch (IOException e)
		{
			log.error("Problem closing socket: " + e.toString(), e);
			throw new RuntimeException(e);
		}
	}
}

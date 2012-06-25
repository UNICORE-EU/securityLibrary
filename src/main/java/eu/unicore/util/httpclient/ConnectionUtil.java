/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.util.httpclient;

import java.io.IOException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.impl.CertificateUtils;
import eu.emi.security.authn.x509.impl.SocketFactoryCreator;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.security.canl.IAuthnAndTrustConfiguration;
import eu.unicore.util.Log;

/**
 * Additional connection related utility methods
 * @author K. Benedyczak
 */
public class ConnectionUtil
{
	/**
	 * Utility method to get a certificate of an SSL peer. The SSL connection is established and if 
	 * successful, the peers identity is returned.
	 * @param securityCfg
	 * @param url
	 * @return certificate
	 * @throws IOException 
	 * @throws UnknownHostException 
	 */
	public static X509Certificate[] getPeerCertificate(IAuthnAndTrustConfiguration securityCfg, String url, 
			int timeout, Logger logger) throws UnknownHostException, IOException {
		if (securityCfg == null || securityCfg.getValidator() == null ||
				securityCfg.getCredential() == null)
			throw new IllegalArgumentException("Can not establish peer's identity " +
					"without having credential and validator set.");
		URL u=new URL(url);
		SSLSocketFactory socketFactory = SocketFactoryCreator.getSocketFactory(
				securityCfg.getCredential(), 
				securityCfg.getValidator());
		SSLSocket s = (SSLSocket) socketFactory.createSocket(u.getHost(), u.getPort());
		s.setSoTimeout(timeout);
		
		X509Certificate[] peer = CertificateUtils.convertToX509Chain(s.getSession().getPeerCertificates());
		if (logger.isDebugEnabled()) {
			try{
				logger.debug("Got peer cert of <"+url+">,\n" +
						"Name: "+
						X500NameUtils.getReadableForm(peer[0].getSubjectX500Principal())+
						"\nIssued by: "+
						X500NameUtils.getReadableForm(peer[0].getIssuerX500Principal()));
			} catch(Exception e) {
				Log.logException("Problem with certificate for <"+url+">",e,logger);
				return null;
			}
		}
		s.close();
		return peer;
	}
}
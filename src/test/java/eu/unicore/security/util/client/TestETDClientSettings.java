/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 21-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import java.security.KeyStore;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import eu.unicore.security.CertificateUtils;
import eu.unicore.security.etd.DelegationRestrictions;

import junit.framework.TestCase;

public class TestETDClientSettings extends TestCase
{
	public void testGenSimple() throws Exception
	{
		KeyStore ks = AuthSSLProtocolSocketFactory.createKeyStore(
				"src/test/resources/client/httpclient.jks", 
				"the!client",
				"JKS", 
				null, false);
		final X509Certificate cert = (X509Certificate) ks.getCertificate("httpclient");
		
		ETDClientSettings settings = new ETDClientSettings();
		X500Principal receiver = new X500Principal("CN=Lem");
		String requestedUserDN = cert.getSubjectX500Principal().getName();
		settings.setRequestedUser(requestedUserDN);
		settings.setReceiver(receiver);
		settings.setExtendTrustDelegation(true);
		settings.setIssuerCertificateChain(c.getCertificateChain());
		
		settings.setDelegationRestrictions(new DelegationRestrictions(null, null, 12));
		settings = settings.clone();
		
		assertTrue(settings.getReceiver().equals(receiver));
		assertTrue(CertificateUtils.dnEqual(cert.getSubjectX500Principal(), settings.getRequestedUser()));
		assertTrue(settings.isExtendTrustDelegation());
		assertTrue(settings.getDelegationRestrictions().getMaxProxyCount() == 12);
		
	}
}

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
		IClientProperties properties = new SimpleClientPropertiesImpl()
		{
			public X509Certificate[] getCertificateChain()
			{
				return new X509Certificate[] {cert};
			}
		};
		settings.initializeSimple(receiver, properties);
		settings.setDelegationRestrictions(new DelegationRestrictions(null, null, 12));
		settings = settings.clone();
		
		assertTrue(settings.getReceiver().equals(receiver));
		assertTrue(new X500Principal(settings.getRequestedUser())
			.equals(cert.getSubjectX500Principal()));
		assertTrue(settings.isExtendTrustDelegation());
		assertTrue(settings.getDelegationRestrictions().getMaxProxyCount() == 12);
		
	}
}

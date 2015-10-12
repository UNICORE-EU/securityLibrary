/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 21-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import static org.junit.Assert.assertTrue;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.junit.Test;

import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.security.etd.DelegationRestrictions;
import eu.unicore.util.httpclient.ETDClientSettings;

public class TestETDClientSettings 
{
	@Test
	public void testGenSimple() throws Exception
	{
		X509Credential c = new KeystoreCredential("src/test/resources/client/httpclient.jks", 
				"the!client".toCharArray(), "the!client".toCharArray(),
				"httpclient", "JKS");
		final X509Certificate cert = c.getCertificate();
		
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
		assertTrue(X500NameUtils.equal(cert.getSubjectX500Principal(), settings.getRequestedUser()));
		assertTrue(settings.isExtendTrustDelegation());
		assertTrue(settings.getDelegationRestrictions().getMaxProxyCount() == 12);
		
	}
}

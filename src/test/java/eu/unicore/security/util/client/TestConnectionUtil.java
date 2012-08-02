/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licensing information.
 */
package eu.unicore.security.util.client;

import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.util.httpclient.ConnectionUtil;
import eu.unicore.util.httpclient.DefaultClientConfiguration;

/**
 * @author K. Benedyczak
 */
public class TestConnectionUtil extends TestCase
{
	private JettyServer4Testing server;
	
	public void setUp() throws Exception
	{
		server = JettyServer4Testing.getInstance(1);
		server.start();
	}
	
	
	public void testGetPeerCertificate()
	{
		try
		{
			System.out.println("\nTest Get SSL Peer\n");
			X509Credential cred = new KeystoreCredential("src/test/resources/client/httpclient.jks",
					"the!client".toCharArray(), "the!client".toCharArray(), null, "JKS");
			X509CertChainValidatorExt validator = new KeystoreCertChainValidator("src/test/resources/client/httpclient.jks",
					"the!client".toCharArray(), "JKS", -1);
			DefaultClientConfiguration secCfg = new DefaultClientConfiguration(validator, cred);
			X509Certificate cert = ConnectionUtil.getPeerCertificate(secCfg,
					server.getSecUrl(), 10000, Logger.getLogger(TestConnectionUtil.class))[0];
			assertNotNull(cert);
			assertTrue(X500NameUtils.equal(cert.getSubjectX500Principal(), 
					server.getSecSettings().getCredential().getCertificate().getSubjectX500Principal().getName()));
		} catch (Throwable e)
		{
			e.printStackTrace();
			fail();
		} finally 
		{
			try
			{
				server.stop();
			} catch (Exception e)
			{
			}
		}
		
	}
}

/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.util.Properties;

import static eu.unicore.security.util.CredentialPropertiesConfig.*;

import junit.framework.TestCase;


public class CredentialPropertiesTest extends TestCase
{
	private static final String PFX = "src/test/resources/credentials/";
	
	public void testPEM()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PFX + PROP_TYPE, TYPE_PEM);
		p.setProperty(DEFAULT_PFX + PROP_LOCATION, PFX+"cert-1.pem");
		p.setProperty(DEFAULT_PFX + PROP_PASSWORD, "the!njs");
		p.setProperty(DEFAULT_PFX + PROP_KEY_LOCATION, PFX+"pk-1.pem");
		verify(p);
	}

	public void testPEM2()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PFX + PROP_TYPE, TYPE_PEM);
		p.setProperty(DEFAULT_PFX + PROP_LOCATION, PFX+"keystore-1.pem");
		p.setProperty(DEFAULT_PFX + PROP_PASSWORD, "the!njs");
		verify(p);
	}
	
	public void testDER()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PFX + PROP_TYPE, TYPE_DER);
		p.setProperty(DEFAULT_PFX + PROP_LOCATION, PFX+"cert-1.der");
		p.setProperty(DEFAULT_PFX + PROP_KEY_LOCATION, PFX+"pk-1.der");
		p.setProperty(DEFAULT_PFX + PROP_PASSWORD, "the!njs");
		verify(p);
	}
	
	public void testJKS()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PFX + PROP_TYPE, TYPE_JKS);
		p.setProperty(DEFAULT_PFX + PROP_LOCATION, PFX+"keystore-1.jks");
		p.setProperty(DEFAULT_PFX + PROP_PASSWORD, "the!njs");
		verify(p);
	}

	public void testPKCS12()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PFX + PROP_TYPE, TYPE_PKCS12);
		p.setProperty(DEFAULT_PFX + PROP_LOCATION, PFX+"keystore-1.p12");
		p.setProperty(DEFAULT_PFX + PROP_PASSWORD, "the!njs");
		p.setProperty(DEFAULT_PFX + PROP_KS_KEY_PASSWORD, "the!njs");
		verify(p);
	}

	private void verify(Properties p)
	{
		try
		{
			CredentialPropertiesConfig cfg = new CredentialPropertiesConfig(p);
			assertNotNull(cfg.getCredential().getCertificate());

			p.remove(DEFAULT_PFX + PROP_TYPE);
			cfg = new CredentialPropertiesConfig(p);
			assertNotNull(cfg.getCredential().getCertificate());
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.toString());
		}
	}
}

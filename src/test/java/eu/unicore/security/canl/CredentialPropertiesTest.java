/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.canl;

import static eu.unicore.security.canl.CredentialProperties.DEFAULT_PREFIX;
import static eu.unicore.security.canl.CredentialProperties.PROP_FORMAT;
import static eu.unicore.security.canl.CredentialProperties.PROP_KEY_LOCATION;
import static eu.unicore.security.canl.CredentialProperties.PROP_KS_ALIAS;
import static eu.unicore.security.canl.CredentialProperties.PROP_KS_KEY_PASSWORD;
import static eu.unicore.security.canl.CredentialProperties.PROP_LOCATION;
import static eu.unicore.security.canl.CredentialProperties.PROP_PASSWORD;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.Properties;

import org.junit.Test;

import eu.unicore.security.canl.CredentialProperties.CredentialFormat;


public class CredentialPropertiesTest
{
	private static final String PFX = "src/test/resources/credentials/";
	
	@Test
	public void testPEM()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_FORMAT, CredentialFormat.pem.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_LOCATION, PFX+"cert-1.pem");
		p.setProperty(DEFAULT_PREFIX + PROP_PASSWORD, "the!njs");
		p.setProperty(DEFAULT_PREFIX + PROP_KEY_LOCATION, PFX+"pk-1.pem");
		verify(p);
	}

	@Test
	public void testPEM2()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_FORMAT, CredentialFormat.pem.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_LOCATION, PFX+"keystore-1.pem");
		p.setProperty(DEFAULT_PREFIX + PROP_PASSWORD, "the!njs");
		verify(p);
	}
	
	@Test
	public void testDER()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_FORMAT, CredentialFormat.der.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_LOCATION, PFX+"cert-1.der");
		p.setProperty(DEFAULT_PREFIX + PROP_KEY_LOCATION, PFX+"pk-1.der");
		p.setProperty(DEFAULT_PREFIX + PROP_PASSWORD, "the!njs");
		verify(p);
	}
	
	@Test
	public void testJKS()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_FORMAT, CredentialFormat.jks.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_LOCATION, PFX+"keystore-1.jks");
		p.setProperty(DEFAULT_PREFIX + PROP_PASSWORD, "the!njs");
		verify(p);
	}

	@Test
	public void testPKCS12()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_FORMAT, CredentialFormat.pkcs12.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_LOCATION, PFX+"keystore-1.p12");
		p.setProperty(DEFAULT_PREFIX + PROP_PASSWORD, "the!njs");
		p.setProperty(DEFAULT_PREFIX + PROP_KS_KEY_PASSWORD, "the!njs");
		verify(p);
	}

	@Test
	public void testDetect()
	{
		Properties p = new Properties();
		//p.setProperty(DEFAULT_PREFIX + PROP_FORMAT, CredentialFormat.pkcs12.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_LOCATION, PFX+"portal.p12");
		p.setProperty(DEFAULT_PREFIX + PROP_PASSWORD, "the!portal");
		p.setProperty(DEFAULT_PREFIX + PROP_KS_ALIAS, "portal");
		verify(p);
	}

	private void verify(Properties p)
	{
		try
		{
			CredentialProperties cfg = new CredentialProperties(p);
			assertNotNull(cfg.getCredential().getCertificate());

			p.remove(DEFAULT_PREFIX + PROP_FORMAT);
			cfg = new CredentialProperties(p);
			assertNotNull(cfg.getCredential().getCertificate());
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.toString());
		}
	}
}

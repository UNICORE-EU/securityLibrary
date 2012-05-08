/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.util.Collections;
import java.util.Properties;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.impl.DirectoryCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;

import static eu.unicore.security.util.TruststoreProperties.*;

import junit.framework.TestCase;


public class TruststorePropertiesTest extends TestCase
{
	private static final String PFX = "src/test/resources/truststores/";
	
	public void testOpenssl()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.openssl.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_OPENSSL_DIR, PFX+"openssl");
		p.setProperty(DEFAULT_PREFIX + PROP_OPENSSL_NS_MODE, "EUGRIDPMA_GLOBUS_REQUIRE");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_MODE, "REQUIRE");
		p.setProperty(DEFAULT_PREFIX + PROP_UPDATE, "1234");
		p.setProperty(DEFAULT_PREFIX + PROP_PROXY_SUPPORT, "DENY");
		
		OpensslCertChainValidator v = (OpensslCertChainValidator) verify(p);
		assertEquals(v.getTruststorePath(), PFX+"openssl");
		assertEquals(v.getUpdateInterval(), 1234000);
		assertEquals(v.getProxySupport(), ProxySupport.DENY);
		assertEquals(v.getNamespaceCheckingMode(), NamespaceCheckingMode.EUGRIDPMA_GLOBUS_REQUIRE);
		assertEquals(v.getRevocationCheckingMode().getCrlCheckingMode(), CrlCheckingMode.REQUIRE);
		assertTrue("Issuers: " + v.getTrustedIssuers().length, v.getTrustedIssuers().length == 1);
	}

	public void testOpensslDefaults()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.openssl.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_OPENSSL_DIR, PFX+"openssl");
		
		OpensslCertChainValidator v = (OpensslCertChainValidator) verify(p);
		assertEquals(v.getTruststorePath(), PFX+"openssl");
		assertEquals(v.getUpdateInterval()+"", 
				TruststoreProperties.META.get(PROP_UPDATE).getDefault()+"000");
		assertEquals(v.getProxySupport().name(), 
				TruststoreProperties.META.get(PROP_PROXY_SUPPORT).getDefault());
		assertEquals(v.getNamespaceCheckingMode().name(), 
			TruststoreProperties.META.get(PROP_OPENSSL_NS_MODE).getDefault());
		assertEquals(v.getRevocationCheckingMode().getCrlCheckingMode().name(), 
			TruststoreProperties.META.get(PROP_CRL_MODE).getDefault());
		
		v.dispose();
	}

	public void testDirectory()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.directory.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_UPDATE, "1234");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_MODE, "REQUIRE");
		p.setProperty(DEFAULT_PREFIX + PROP_PROXY_SUPPORT, "DENY");

		p.setProperty(DEFAULT_PREFIX + PROP_DIRECTORY_LOCATIONS, PFX+"dir/*.pem");
		p.setProperty(DEFAULT_PREFIX + PROP_DIRECTORY_CACHE_PATH, "/tmp");
		p.setProperty(DEFAULT_PREFIX + PROP_DIRECTORY_CONNECTION_TIMEOUT, "100");
		p.setProperty(DEFAULT_PREFIX + PROP_DIRECTORY_ENCODING, "PEM");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_CACHE_PATH, "/tmp");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_CONNECTION_TIMEOUT, "200");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_LOCATIONS, PFX+"dir/*.crl");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_UPDATE, "400");
		
		DirectoryCertChainValidator v = (DirectoryCertChainValidator) verify(p);
		assertEquals(v.getTruststorePaths().get(0), PFX+"dir/*.pem");
		assertEquals(v.getTruststoreUpdateInterval(), 1234000);
		assertEquals(v.getProxySupport(), ProxySupport.DENY);
		assertEquals(v.getRevocationCheckingMode().getCrlCheckingMode(), CrlCheckingMode.REQUIRE);
		assertEquals(v.getRevocationParameters().getCrlParameters().getCrlUpdateInterval() + "", 
			"400");
		assertEquals(v.getRevocationParameters().getCrlParameters().getCrls().get(0), 
			PFX+"dir/*.crl");
		assertEquals(v.getRevocationParameters().getCrlParameters().getDiskCachePath(), 
				"/tmp");
		assertTrue("Issuers: " + v.getTrustedIssuers().length, v.getTrustedIssuers().length == 1);
		v.dispose();
	}

	public void testDirectoryDefaults()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.directory.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_DIRECTORY_LOCATIONS, PFX+"dir/*.pem");
		
		DirectoryCertChainValidator v = (DirectoryCertChainValidator) verify(p);
		assertEquals(v.getTruststorePaths().get(0), PFX+"dir/*.pem");
		assertEquals(v.getTruststoreUpdateInterval()+"", 
				TruststoreProperties.META.get(PROP_UPDATE).getDefault()+"000");
		assertEquals(v.getProxySupport().name(), 
				TruststoreProperties.META.get(PROP_PROXY_SUPPORT).getDefault());
		assertEquals(v.getRevocationCheckingMode().getCrlCheckingMode().name(), 
			TruststoreProperties.META.get(PROP_CRL_MODE).getDefault());
		assertEquals(v.getRevocationParameters().getCrlParameters().getCrlUpdateInterval() + "", 
			TruststoreProperties.META.get(PROP_CRL_UPDATE).getDefault());
		assertEquals(v.getRevocationParameters().getCrlParameters().getDiskCachePath(), 
				null);
		assertTrue("Issuers: " + v.getTrustedIssuers().length, v.getTrustedIssuers().length == 1);
		v.dispose();
	}

	public void testJKS()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.keystore.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_KS_PATH, PFX+"truststore1.jks");
		p.setProperty(DEFAULT_PREFIX + PROP_KS_PASSWORD, "the!njs");
		KeystoreCertChainValidator v = (KeystoreCertChainValidator) verify(p);
		assertEquals(v.getTruststorePath(), PFX+"truststore1.jks");
		assertEquals(v.getTruststoreUpdateInterval()+"", 
			TruststoreProperties.META.get(PROP_UPDATE).getDefault()+"000");
	}
	
	public void testPKCS12()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.keystore.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_KS_PATH, PFX+"keystore-1.p12");
		p.setProperty(DEFAULT_PREFIX + PROP_KS_PASSWORD, "the!njs");
		KeystoreCertChainValidator v = (KeystoreCertChainValidator) verify(p);
		assertEquals(v.getTruststorePath(), PFX+"keystore-1.p12");
		assertEquals(v.getTruststoreUpdateInterval()+"", 
			TruststoreProperties.META.get(PROP_UPDATE).getDefault()+"000");
	}

	private X509CertChainValidator verify(Properties p)
	{
		try
		{
			TruststoreProperties cfg = new TruststoreProperties(p, 
				Collections.singleton(new LoggingStoreUpdateListener()));
			assertNotNull(cfg.getValidator());
			return cfg.getValidator();
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.toString());
			return null;
		}
	}
}

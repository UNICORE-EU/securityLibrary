/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.canl;

import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_DIRECTORY_CACHE_PATH;
import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_DIRECTORY_CONNECTION_TIMEOUT;
import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_DIRECTORY_ENCODING;
import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_DIRECTORY_LOCATIONS;
import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_KS_PASSWORD;
import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_KS_PATH;
import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_OPENSSL_DIR;
import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_TYPE;
import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_UPDATE;
import static eu.unicore.security.canl.TruststoreProperties.DEFAULT_PREFIX;
import static eu.unicore.security.canl.TruststoreProperties.PROP_CRL_CACHE_PATH;
import static eu.unicore.security.canl.TruststoreProperties.PROP_CRL_CONNECTION_TIMEOUT;
import static eu.unicore.security.canl.TruststoreProperties.PROP_CRL_LOCATIONS;
import static eu.unicore.security.canl.TruststoreProperties.PROP_CRL_MODE;
import static eu.unicore.security.canl.TruststoreProperties.PROP_CRL_UPDATE;
import static eu.unicore.security.canl.TruststoreProperties.PROP_OCSP_LOCAL_RESPONDERS;
import static eu.unicore.security.canl.TruststoreProperties.PROP_OPENSSL_NS_MODE;
import static eu.unicore.security.canl.TruststoreProperties.PROP_PROXY_SUPPORT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import eu.emi.security.authn.x509.CrlCheckingMode;
import eu.emi.security.authn.x509.NamespaceCheckingMode;
import eu.emi.security.authn.x509.ProxySupport;
import eu.emi.security.authn.x509.impl.DirectoryCertChainValidator;
import eu.emi.security.authn.x509.impl.InMemoryKeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.OpensslCertChainValidator;
import eu.unicore.security.canl.TrustedIssuersProperties.TruststoreType;


public class TruststorePropertiesTest
{

	private static final String PFX = "src/test/resources/truststores/";

	@Test
	public void testOpenssl() throws Exception
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.openssl.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_OPENSSL_DIR, PFX+"openssl");
		p.setProperty(DEFAULT_PREFIX + PROP_OPENSSL_NS_MODE, "EUGRIDPMA_GLOBUS_REQUIRE");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_MODE, "REQUIRE");
		p.setProperty(DEFAULT_PREFIX + PROP_UPDATE, "1234");
		p.setProperty(DEFAULT_PREFIX + PROP_PROXY_SUPPORT, "DENY");

		OpensslCertChainValidator v = (OpensslCertChainValidator) verify(p).getValidator();
		assertEquals(v.getTruststorePath(), PFX+"openssl");
		assertEquals(v.getUpdateInterval(), 1234000);
		assertEquals(v.getProxySupport(), ProxySupport.DENY);
		assertEquals(v.getNamespaceCheckingMode(), NamespaceCheckingMode.EUGRIDPMA_GLOBUS_REQUIRE);
		assertEquals(v.getRevocationCheckingMode().getCrlCheckingMode(), CrlCheckingMode.REQUIRE);
		assertTrue(v.getTrustedIssuers().length == 1);
	}

	@Test
	public void testOpensslDefaults() throws Exception
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.openssl.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_OPENSSL_DIR, PFX+"openssl");

		OpensslCertChainValidator v = (OpensslCertChainValidator) verify(p).getValidator();
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

	@Test
	public void testDirectory() throws Exception
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.directory.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_UPDATE, "1234");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_MODE, "REQUIRE");
		p.setProperty(DEFAULT_PREFIX + PROP_PROXY_SUPPORT, "DENY");

		p.setProperty(DEFAULT_PREFIX + PROP_DIRECTORY_LOCATIONS + "1", PFX+"dir/*.pem");
		p.setProperty(DEFAULT_PREFIX + PROP_DIRECTORY_CACHE_PATH, "/tmp");
		p.setProperty(DEFAULT_PREFIX + PROP_DIRECTORY_CONNECTION_TIMEOUT, "100");
		p.setProperty(DEFAULT_PREFIX + PROP_DIRECTORY_ENCODING, "PEM");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_CACHE_PATH, "/tmp");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_CONNECTION_TIMEOUT, "200");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_LOCATIONS + "1", PFX+"dir/*.crl");
		p.setProperty(DEFAULT_PREFIX + PROP_CRL_UPDATE, "400");

		p.setProperty(DEFAULT_PREFIX + PROP_OCSP_LOCAL_RESPONDERS + "1", "http://some.responder/foo src/test/resources/credentials/cert-1.pem");
		p.setProperty(DEFAULT_PREFIX + PROP_OCSP_LOCAL_RESPONDERS + "2", "http://some.responder/bar src/test/resources/credentials/cert-1.pem");

		TruststoreProperties tp = verify(p);
		DirectoryCertChainValidator v = (DirectoryCertChainValidator) tp.getValidator();
		assertEquals(v.getTruststorePaths().get(0), PFX+"dir/*.pem");
		assertEquals(v.getTruststoreUpdateInterval(), 1234000);
		assertEquals(v.getProxySupport(), ProxySupport.DENY);
		assertEquals(v.getRevocationCheckingMode().getCrlCheckingMode(), CrlCheckingMode.REQUIRE);
		assertEquals(v.getRevocationParameters().getCrlParameters().getCrlUpdateInterval() + "", 
				"400000");
		assertEquals(v.getRevocationParameters().getCrlParameters().getCrls().get(0), 
				PFX+"dir/*.crl");
		assertEquals(v.getRevocationParameters().getCrlParameters().getDiskCachePath(), 
				"/tmp");
		assertTrue(v.getTrustedIssuers().length == 1);
		assertEquals(2, v.getRevocationParameters().getOcspParameters().getLocalResponders().length);

		//test update
		tp.setProperty(PROP_UPDATE, "12");
		tp.setProperty(PROP_DIRECTORY_LOCATIONS + "1", PFX+"dir/ss*.pem");
		tp.setProperty(PROP_CRL_LOCATIONS + "1", PFX+"dir/ss*.crl");
		tp.setProperty(PROP_CRL_UPDATE, "40");
		v = (DirectoryCertChainValidator) tp.getValidator();

		assertEquals(12000, v.getTruststoreUpdateInterval());
		assertEquals("40000", v.getRevocationParameters().getCrlParameters().getCrlUpdateInterval() + "");
		assertEquals(PFX+"dir/ss*.pem", v.getTruststorePaths().get(0));
		assertEquals(PFX+"dir/ss*.crl", v.getRevocationParameters().getCrlParameters().getCrls().get(0));

		v.dispose();
	}

	@Test
	public void testDirectoryDefaults() throws Exception
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.directory.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_DIRECTORY_LOCATIONS, PFX+"dir/*.pem");

		DirectoryCertChainValidator v = (DirectoryCertChainValidator) verify(p).getValidator();
		assertEquals(v.getTruststorePaths().get(0), PFX+"dir/*.pem");
		assertEquals(v.getTruststoreUpdateInterval()+"", 
				TruststoreProperties.META.get(PROP_UPDATE).getDefault()+"000");
		assertEquals(v.getProxySupport().name(), 
				TruststoreProperties.META.get(PROP_PROXY_SUPPORT).getDefault());
		assertEquals(v.getRevocationCheckingMode().getCrlCheckingMode().name(), 
				TruststoreProperties.META.get(PROP_CRL_MODE).getDefault());
		assertEquals(v.getRevocationParameters().getCrlParameters().getCrlUpdateInterval() + "", 
				TruststoreProperties.META.get(PROP_CRL_UPDATE).getDefault()+"000");
		assertEquals(v.getRevocationParameters().getCrlParameters().getDiskCachePath(), 
				null);
		assertTrue(v.getTrustedIssuers().length == 1);
		v.dispose();
	}

	@Test
	public void testJKS() throws Exception
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.keystore.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_KS_PATH, PFX+"truststore1.jks");
		p.setProperty(DEFAULT_PREFIX + PROP_KS_PASSWORD, "the!njs");
		KeystoreCertChainValidator v = (KeystoreCertChainValidator) verify(p).getValidator();
		assertEquals(v.getTruststorePath(), PFX+"truststore1.jks");
		assertEquals(v.getTruststoreUpdateInterval()+"", 
				TruststoreProperties.META.get(PROP_UPDATE).getDefault()+"000");
	}

	@Test
	public void testPKCS12() throws Exception
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.keystore.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_KS_PATH, PFX+"keystore-1.p12");
		p.setProperty(DEFAULT_PREFIX + PROP_KS_PASSWORD, "the!njs");
		KeystoreCertChainValidator v = (KeystoreCertChainValidator) verify(p).getValidator();
		assertEquals(v.getTruststorePath(), PFX+"keystore-1.p12");
		assertEquals(v.getTruststoreUpdateInterval()+"", 
				TruststoreProperties.META.get(PROP_UPDATE).getDefault()+"000");
	}

	@Test
	public void testJDKDefaultCerts() throws Exception
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX + PROP_TYPE, TruststoreType.builtin.toString());
		InMemoryKeystoreCertChainValidator v = (InMemoryKeystoreCertChainValidator) verify(p).getValidator();
		assertTrue(v.getTrustedIssuers().length > 0);
		v.dispose();
	}

	private TruststoreProperties verify(Properties p) throws Exception
	{
		TruststoreProperties cfg = new TruststoreProperties(p, 
				Collections.singleton(new LoggingStoreUpdateListener()));
		assertNotNull(cfg.getValidator());
		return cfg;
	}
}

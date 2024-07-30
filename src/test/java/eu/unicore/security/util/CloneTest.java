/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import static eu.unicore.security.canl.CredentialProperties.DEFAULT_PREFIX;
import static eu.unicore.security.canl.CredentialProperties.PROP_FORMAT;
import static eu.unicore.security.canl.CredentialProperties.PROP_LOCATION;
import static eu.unicore.security.canl.CredentialProperties.PROP_PASSWORD;
import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_KS_PASSWORD;
import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_KS_PATH;
import static eu.unicore.security.canl.TrustedIssuersProperties.PROP_TYPE;
import static eu.unicore.util.httpclient.ClientProperties.PROP_HTTP_AUTHN_ENABLED;
import static eu.unicore.util.httpclient.ClientProperties.PROP_HTTP_PASSWORD;
import static eu.unicore.util.httpclient.ClientProperties.PROP_HTTP_USER;
import static eu.unicore.util.httpclient.ClientProperties.PROP_MESSAGE_SIGNING_ENABLED;
import static eu.unicore.util.httpclient.ClientProperties.PROP_SERVER_HOSTNAME_CHECKING;
import static eu.unicore.util.httpclient.ClientProperties.PROP_SSL_AUTHN_ENABLED;
import static eu.unicore.util.httpclient.ClientProperties.PROP_SSL_ENABLED;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import eu.unicore.security.canl.AuthnAndTrustProperties;
import eu.unicore.security.canl.CredentialProperties;
import eu.unicore.security.canl.CredentialProperties.CredentialFormat;
import eu.unicore.security.canl.DefaultAuthnAndTrustConfiguration;
import eu.unicore.security.canl.LoggingStoreUpdateListener;
import eu.unicore.security.canl.TrustedIssuersProperties;
import eu.unicore.security.canl.TruststoreProperties;
import eu.unicore.util.httpclient.ClientProperties;

public class CloneTest
{
	private void testByReflection(Object src, Object cloned) throws Exception
	{
		assertEquals(src.getClass(), cloned.getClass());
			
		Field[] fields = src.getClass().getFields();
		for (Field field: fields)
		{
			field.setAccessible(true);
			Object srcFVal = field.get(src);
			Object clonedFVal = field.get(cloned);
			assertEquals(srcFVal, clonedFVal, "Field not copied correctly "+field);
		}
	}
	
	@Test
	public void testClone() throws Exception
	{
		Properties p = new Properties();
		p.setProperty(ClientProperties.DEFAULT_PREFIX+PROP_HTTP_AUTHN_ENABLED, "true");
		p.setProperty(ClientProperties.DEFAULT_PREFIX+PROP_HTTP_PASSWORD, "pass");
		p.setProperty(ClientProperties.DEFAULT_PREFIX+PROP_HTTP_USER, "user");
		p.setProperty(ClientProperties.DEFAULT_PREFIX+PROP_MESSAGE_SIGNING_ENABLED, "false");
		p.setProperty(ClientProperties.DEFAULT_PREFIX+PROP_SERVER_HOSTNAME_CHECKING, "FAIL");
		p.setProperty(ClientProperties.DEFAULT_PREFIX+PROP_SSL_AUTHN_ENABLED, "false");
		p.setProperty(ClientProperties.DEFAULT_PREFIX+PROP_SSL_ENABLED, "false");
		
		ClientProperties cp = new ClientProperties(p, new DefaultAuthnAndTrustConfiguration());
		testByReflection(cp, cp.clone());

		p.setProperty(TruststoreProperties.DEFAULT_PREFIX + PROP_TYPE, 
				TrustedIssuersProperties.TruststoreType.keystore.toString());
		p.setProperty(TruststoreProperties.DEFAULT_PREFIX + PROP_KS_PATH, "src/test/resources/truststores/truststore1.jks");
		p.setProperty(TruststoreProperties.DEFAULT_PREFIX + PROP_KS_PASSWORD, "the!njs");
		TruststoreProperties cfg = new TruststoreProperties(p, 
				Collections.singleton(new LoggingStoreUpdateListener()));
		testByReflection(cfg, cfg.clone());
		
		p.setProperty(DEFAULT_PREFIX + PROP_FORMAT, CredentialFormat.jks.toString());
		p.setProperty(DEFAULT_PREFIX + PROP_LOCATION, "src/test/resources/credentials/keystore-1.jks");
		p.setProperty(DEFAULT_PREFIX + PROP_PASSWORD, "the!njs");
		CredentialProperties cred = new CredentialProperties(p);
		testByReflection(cred, cred.clone());
		
		AuthnAndTrustProperties at = new AuthnAndTrustProperties(p);
		testByReflection(at, at.clone());
		
		testByReflection(at.getCredentialProperties(), at.clone().getCredentialProperties());
		testByReflection(at.getTruststoreProperties(), at.clone().getTruststoreProperties());
	}
}

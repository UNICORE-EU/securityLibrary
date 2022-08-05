/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.httpclient;

import static eu.unicore.util.httpclient.ClientProperties.DEFAULT_PREFIX;
import static eu.unicore.util.httpclient.ClientProperties.PROP_HTTP_AUTHN_ENABLED;
import static eu.unicore.util.httpclient.ClientProperties.PROP_HTTP_PASSWORD;
import static eu.unicore.util.httpclient.ClientProperties.PROP_HTTP_USER;
import static eu.unicore.util.httpclient.ClientProperties.PROP_MESSAGE_SIGNING_ENABLED;
import static eu.unicore.util.httpclient.ClientProperties.PROP_SERVER_HOSTNAME_CHECKING;
import static eu.unicore.util.httpclient.ClientProperties.PROP_SSL_AUTHN_ENABLED;
import static eu.unicore.util.httpclient.ClientProperties.PROP_SSL_ENABLED;
import static org.junit.Assert.assertEquals;

import java.util.Properties;

import org.junit.Test;

import eu.unicore.security.canl.DefaultAuthnAndTrustConfiguration;
import eu.unicore.util.httpclient.ClientProperties;
import eu.unicore.util.httpclient.ServerHostnameCheckingMode;
import eu.unicore.util.httpclient.SessionIDProviderImpl;


public class ClientPropertiesTest
{
	@Test
	public void test()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX+PROP_HTTP_AUTHN_ENABLED, "true");
		p.setProperty(DEFAULT_PREFIX+PROP_HTTP_PASSWORD, "pass");
		p.setProperty(DEFAULT_PREFIX+PROP_HTTP_USER, "user");
		p.setProperty(DEFAULT_PREFIX+PROP_MESSAGE_SIGNING_ENABLED, "false");
		p.setProperty(DEFAULT_PREFIX+PROP_SERVER_HOSTNAME_CHECKING, "FAIL");
		p.setProperty(DEFAULT_PREFIX+PROP_SSL_AUTHN_ENABLED, "false");
		p.setProperty(DEFAULT_PREFIX+PROP_SSL_ENABLED, "false");
		
		ClientProperties cp = new ClientProperties(p, new DefaultAuthnAndTrustConfiguration());
		assertEquals(true, cp.doHttpAuthn());
		assertEquals("pass", cp.getHttpPassword());
		assertEquals("user", cp.getHttpUser());
		assertEquals(false, cp.doSignMessage());
		assertEquals(false, cp.doSSLAuthn());
		assertEquals(false, cp.isSslEnabled());
		assertEquals(ServerHostnameCheckingMode.FAIL, cp.getServerHostnameCheckingMode());
	}

	@Test
	public void testSessionIDProviderImpl(){
		String url = "https://gw:123/SITE/services/x/y";
		assertEquals("https://gw:123/SITE/services", SessionIDProviderImpl.extractServerID(url));
		url = "https://gw:123/SITE/rest/core";
		assertEquals("https://gw:123/SITE/services", SessionIDProviderImpl.extractServerID(url));
		url = "https://gw:123/SITE";
		assertEquals("https://gw:123/SITE", SessionIDProviderImpl.extractServerID(url));
	}
}

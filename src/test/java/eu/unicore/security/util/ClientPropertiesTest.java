/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util;

import java.util.Arrays;
import java.util.Properties;

import eu.unicore.security.canl.DefaultAuthnAndTrustConfiguration;
import eu.unicore.security.util.client.ClientProperties;
import eu.unicore.security.util.client.ServerHostnameCheckingMode;
import static eu.unicore.security.util.client.ClientProperties.*;

import junit.framework.TestCase;


public class ClientPropertiesTest extends TestCase
{
	public void test()
	{
		Properties p = new Properties();
		p.setProperty(DEFAULT_PREFIX+PROP_HTTP_AUTHN_ENABLED, "true");
		p.setProperty(DEFAULT_PREFIX+PROP_HTTP_PASSWORD, "pass");
		p.setProperty(DEFAULT_PREFIX+PROP_HTTP_USER, "user");
		p.setProperty(DEFAULT_PREFIX+PROP_IN_HANDLERS, "h1 h2");
		p.setProperty(DEFAULT_PREFIX+PROP_MESSAGE_SIGNING_ENABLED, "false");
		p.setProperty(DEFAULT_PREFIX+PROP_OUT_HANDLERS, "h1");
		p.setProperty(DEFAULT_PREFIX+PROP_SERVER_HOSTNAME_CHECKING, "FAIL");
		p.setProperty(DEFAULT_PREFIX+PROP_SSL_AUTHN_ENABLED, "false");
		p.setProperty(DEFAULT_PREFIX+PROP_SSL_ENABLED, "false");
		p.setProperty(DEFAULT_PREFIX+EXTRA_HTTP_LIB_PROPERTIES_PREFIX+"dfsf", "foo");
		
		ClientProperties cp = new ClientProperties(p, new DefaultAuthnAndTrustConfiguration());
		assertEquals(true, cp.doHttpAuthn());
		assertEquals("pass", cp.getHttpPassword());
		assertEquals("user", cp.getHttpUser());
		assertTrue(Arrays.equals(new String[] {"h1", "h2"}, cp.getInHandlerClassNames()));
		assertTrue(Arrays.equals(new String[] {"h1"}, cp.getOutHandlerClassNames()));
		assertEquals(false, cp.doSignMessage());
		assertEquals(false, cp.doSSLAuthn());
		assertEquals(false, cp.isSslEnabled());
		assertEquals(ServerHostnameCheckingMode.FAIL, cp.getServerHostnameCheckingMode());
		assertEquals(1, cp.getExtraSettings().size());
		assertEquals("foo", cp.getExtraSettings().get("http.dfsf"));
	}

}

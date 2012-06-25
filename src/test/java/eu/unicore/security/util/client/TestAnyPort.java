/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.client;

import junit.framework.TestCase;

public class TestAnyPort extends TestCase
{
	public void testAnyPort() throws Exception
	{
		JettyServer4Testing server = JettyServer4Testing.getAnyPortInstance(1);
		assertEquals(0, server.getUrls()[0].getPort());
		server.start();
		assertNotSame(0, server.getUrls()[0].getPort());
		server.stop();
	}
}

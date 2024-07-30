/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import org.junit.jupiter.api.Test;

public class TestAnyPort 
{
	@Test
	public void testAnyPort() throws Exception
	{
		JettyServer4Testing server = JettyServer4Testing.getAnyPortInstance();
		assertEquals(0, server.getUrls()[0].getPort());
		server.start();
		assertNotSame(0, server.getUrls()[0].getPort());
		server.stop();
	}
}

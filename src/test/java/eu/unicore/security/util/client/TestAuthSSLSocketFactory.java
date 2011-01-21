package eu.unicore.security.util.client;

import java.security.KeyStore;
import java.util.Enumeration;

import eu.unicore.security.util.client.AuthSSLProtocolSocketFactory;

public class TestAuthSSLSocketFactory extends junit.framework.TestCase
{

	public void test1() throws Exception
	{
		try
		{
			KeyStore ks = AuthSSLProtocolSocketFactory.createKeyStore(
					"src/test/resources/client/demo_keystore",
					"demo123", "jks", null, true);
			Enumeration<String> en = ks.aliases();
			assertTrue(en.hasMoreElements());
			String alias = en.nextElement();
			assertEquals("jetty", alias);
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	public void test2() throws Exception
	{
		try
		{
			KeyStore ks = AuthSSLProtocolSocketFactory.createKeyStore(
					"src/test/resources/client/demo_keystore",
					"demo123", "jks", "jetty", false);
			Enumeration<String> en = ks.aliases();
			assertTrue(en.hasMoreElements());
			String alias = en.nextElement();
			assertEquals("jetty", alias);
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	public void testP12() throws Exception
	{
		try
		{
			KeyStore ks = AuthSSLProtocolSocketFactory.createKeyStore(
					"src/test/resources/client/server-keystore.p12",
					"the!njs", "pkcs12", null, true);
			Enumeration<String> en = ks.aliases();
			assertTrue(en.hasMoreElements());
			String alias = en.nextElement();
			assertEquals("njs test certificate", alias);
			assertFalse(en.hasMoreElements());
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.getMessage());
		}
	}
}

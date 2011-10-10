package eu.unicore.security.util.client;

import java.security.KeyStore;

import junit.framework.TestCase;
import eu.unicore.security.util.KeystoreUtil;

public class TestKeystoreUtils extends TestCase{

	public void testInferKSType()throws Exception{
		String name="src/test/resources/client/server-keystore.p12";
		String password="the!njs";
		KeyStore ks=KeystoreUtil.loadKeyStore(name, password, null);
		assertNotNull(ks);
		assertTrue(ks.aliases().hasMoreElements());
	}
	public void testInferKSType2()throws Exception{
		String name="src/test/resources/client/demo_keystore";
		String password="demo123";
		KeyStore ks=KeystoreUtil.loadKeyStore(name, password, null);
		assertNotNull(ks);
		assertTrue(ks.aliases().hasMoreElements());
	}
	
	public void testInferTSTypePEM()throws Exception{
		String name="src/test/resources/client/server.pem";
		String password="unused";
		KeyStore ks=KeystoreUtil.loadTruststore(name, password, null);
		assertNotNull(ks);
		assertTrue(ks.aliases().hasMoreElements());
	}
	
}

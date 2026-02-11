package eu.unicore.security.util.client;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.cert.X509Certificate;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.emi.security.authn.x509.impl.X500NameUtils;
import eu.unicore.util.Log;
import eu.unicore.util.httpclient.ConnectionUtil;
import eu.unicore.util.httpclient.DefaultClientConfiguration;

/**
 * @author K. Benedyczak
 */
public class TestConnectionUtil 
{
	private JettyServer4Testing server;

	@BeforeEach
	public void setUp() throws Exception
	{
		server = JettyServer4Testing.getInstance();
		server.start();
	}

	@AfterEach
	public void tearDown() throws Exception
	{
		server.stop();
	}

	@Test
	public void testGetPeerCertificate() throws Exception
	{
		System.out.println("\nTest Get SSL Peer\n");
		X509Credential cred = new KeystoreCredential("src/test/resources/client/httpclient.jks",
				"the!client".toCharArray(), "the!client".toCharArray(), null, "JKS");
		X509CertChainValidatorExt validator = new KeystoreCertChainValidator("src/test/resources/client/httpclient.jks",
				"the!client".toCharArray(), "JKS", -1);
		DefaultClientConfiguration secCfg = new DefaultClientConfiguration(validator, cred);
		X509Certificate cert = ConnectionUtil.getPeerCertificate(secCfg,
				server.getSecUrl(), 10000, Log.getLogger("",TestConnectionUtil.class))[0];
		assertNotNull(cert);
		assertTrue(X500NameUtils.equal(cert.getSubjectX500Principal(), 
				server.getSecSettings().getCredential().getCertificate().getSubjectX500Principal().getName()));
	}
}

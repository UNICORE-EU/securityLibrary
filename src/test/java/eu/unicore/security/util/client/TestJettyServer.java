package eu.unicore.security.util.client;

import static org.junit.jupiter.api.Assertions.*;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Properties;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpTrace;
import org.apache.hc.client5.http.impl.classic.BasicHttpClientResponseHandler;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.junit.jupiter.api.Test;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.unicore.util.httpclient.DefaultClientConfiguration;
import eu.unicore.util.httpclient.HttpClientProperties;
import eu.unicore.util.httpclient.HttpUtils;
import eu.unicore.util.jetty.HttpServerProperties;

/**
 * Tests Jetty server features
 * 
 * @author K. Benedyczak
 */
public class TestJettyServer 
{

	private void makeRequest(JettyServer4Testing server, boolean shouldBeOk, 
			Class<? extends Exception> expected, boolean useClientCred) throws Exception
	{
		try
		{
			X509Credential cred = new KeystoreCredential("src/test/resources/client/httpclient.jks",
					"the!client".toCharArray(), "the!client".toCharArray(), null, "JKS");
			X509CertChainValidatorExt validator = new KeystoreCertChainValidator("src/test/resources/client/httpclient.jks",
					"the!client".toCharArray(), "JKS", -1);
			DefaultClientConfiguration secCfg = new DefaultClientConfiguration(validator, cred);
			secCfg.getHttpClientProperties().setProperty(HttpClientProperties.CONNECT_TIMEOUT, "2000");
			secCfg.getHttpClientProperties().setProperty(HttpClientProperties.SO_TIMEOUT, "2000");
			secCfg.setSslAuthn(useClientCred);
			
			String url = server.getSecUrl()+"/servlet1";
			HttpClient client = HttpUtils.createClient(url, secCfg);
			HttpGet get = new HttpGet(url);
			String resp = client.execute(get, new BasicHttpClientResponseHandler());
			if (shouldBeOk)
				assertTrue(SimpleServlet.OK_GET.equals(resp));
			else
				fail("Should get an exception");

		} catch (Exception e)
		{
			if (!expected.isAssignableFrom(e.getClass()))
			{ 
				e.printStackTrace();
				System.out.println("***** WARN Should get OTHER exception "+expected.getName()+", got "+e.getClass());
			}
		} finally
		{
			server.stop();
		}
	}
	
	private JettyServer4Testing prepareServer(Properties p1) throws Exception
	{
		JettyServer4Testing server = JettyServer4Testing.getInstance(p1, 65432);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		return server;
	}

	@Test
	public void testSSLNio() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		JettyServer4Testing server = prepareServer(p1);
		makeRequest(server, true, null, true);
	}
	
	@Test
	public void testGzip() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		p1.setProperty("j." + HttpServerProperties.ENABLE_GZIP, "true");
		p1.setProperty("j." + HttpServerProperties.MIN_GZIP_SIZE, "10");
		
		JettyServer4Testing server = prepareServer(p1);
		String url = server.getUrl();
		try
		{
			URL u = new URL(url+"/servlet1?gobig");
			HttpURLConnection conn = (HttpURLConnection) u.openConnection();
			conn.addRequestProperty("Accept-Encoding", "compress, gzip");
			InputStream is = conn.getInputStream();
			int first = is.read();
			int len = 1;
			while (is.read() != -1)
				len++;
			System.out.println("\n" + conn.getContentType());
			System.out.println(conn.getContentLength() + " read " + len);
			assertNotSame('O', (char)first);

			u = new URL(url+"/servlet1");
			conn = (HttpURLConnection) u.openConnection();
			conn.addRequestProperty("Accept-Encoding", "compress, gzip");
			is = conn.getInputStream();
			first = is.read();
			len = 1;
			while (is.read() != -1)
				len++;
			System.out.println("\n" + conn.getContentType());
			System.out.println(conn.getContentLength() + " read " + len);
			assertEquals('O', (char)first);
		} finally
		{
			server.stop();
		}
	}
	
	@Test
	public void testDisabledCiphers() throws Exception
	{
		SSLContext context = SSLContext.getDefault();
		SSLSocketFactory sf = context.getSocketFactory();
		String[] cipherSuites = sf.getSupportedCipherSuites();
		StringBuilder allCiphers = new StringBuilder(cipherSuites[0]);
		for (int i=1; i<cipherSuites.length; i++)
			allCiphers.append(" ").append(cipherSuites[i]);
		
		Properties p1 = JettyServer4Testing.getSecureProperties();
		p1.setProperty("j." + HttpServerProperties.DISABLED_CIPHER_SUITES, allCiphers.toString());
		JettyServer4Testing server = prepareServer(p1);
		try{
			makeRequest(server, false, SSLPeerUnverifiedException.class, true);
		}
		finally{
			server.stop();
		}
	}
	
	@Test
	public void testDisabledTRACE() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		JettyServer4Testing server = prepareServer(p1);
		try{
			String url = server.getSecUrl()+"/servlet1";
			X509Credential cred = new KeystoreCredential("src/test/resources/client/httpclient.jks",
					"the!client".toCharArray(), "the!client".toCharArray(), null, "JKS");
			X509CertChainValidatorExt validator = new KeystoreCertChainValidator("src/test/resources/client/httpclient.jks",
					"the!client".toCharArray(), "JKS", -1);
			DefaultClientConfiguration secCfg = new DefaultClientConfiguration(validator, cred);
			HttpClient client = HttpUtils.createClient(url, secCfg);
			HttpTrace tr = new HttpTrace(url);
			ClassicHttpResponse response = client.executeOpen(null, tr, null);
			assertTrue(HttpServletResponse.SC_METHOD_NOT_ALLOWED==response.getCode());
			response.close();
		}
		finally{
			server.stop();
		}
	}
	
	@Test
	public void testClientAuthn() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		p1.setProperty("j." + HttpServerProperties.WANT_CLIENT_AUTHN, "false");
		p1.setProperty("j." + HttpServerProperties.REQUIRE_CLIENT_AUTHN, "false");

		System.out.println("Authn want: NO require: NO");
		JettyServer4Testing server = JettyServer4Testing.getInstance(p1, 65432);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, true);
		
		server = JettyServer4Testing.getInstance(p1, 65432);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, false);
		
		p1.setProperty("j." + HttpServerProperties.WANT_CLIENT_AUTHN, "true");
		p1.setProperty("j." + HttpServerProperties.REQUIRE_CLIENT_AUTHN, "false");
		System.out.println("Authn want: YES require: NO");
		
		server = JettyServer4Testing.getInstance(p1, 65432);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, true);
		
		server = JettyServer4Testing.getInstance(p1, 65432);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, false);
		
		p1.setProperty("j." + HttpServerProperties.WANT_CLIENT_AUTHN, "true");
		p1.setProperty("j." + HttpServerProperties.REQUIRE_CLIENT_AUTHN, "true");
		System.out.println("Authn want: YES require: YES");
		
		server = JettyServer4Testing.getInstance(p1, 65432);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, true);
		
		server = JettyServer4Testing.getInstance(p1, 65432);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, false, SSLException.class, false);
	}

}

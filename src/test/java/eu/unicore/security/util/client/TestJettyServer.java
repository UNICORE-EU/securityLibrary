/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.client;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Properties;

import javax.net.ssl.SSLPeerUnverifiedException;

import junit.framework.TestCase;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.unicore.util.httpclient.DefaultClientConfiguration;
import eu.unicore.util.httpclient.HttpUtils;
import eu.unicore.util.jetty.JettyProperties;

/**
 * Tests Jetty server features
 * 
 * @author K. Benedyczak
 */
public class TestJettyServer extends TestCase
{
	private void makeRequest(JettyServer4Testing server, boolean shouldBeOk, Class<? extends Exception> expected, boolean useClientCred) throws Exception
	{
		try
		{
			X509Credential cred = new KeystoreCredential("src/test/resources/client/httpclient.jks",
					"the!client".toCharArray(), "the!client".toCharArray(), null, "JKS");
			X509CertChainValidatorExt validator = new KeystoreCertChainValidator("src/test/resources/client/httpclient.jks",
					"the!client".toCharArray(), "JKS", -1);
			DefaultClientConfiguration secCfg = new DefaultClientConfiguration(validator, cred);
			secCfg.getExtraSettings().setProperty(HttpUtils.CONNECT_TIMEOUT, "2000");
			secCfg.getExtraSettings().setProperty(HttpUtils.SO_TIMEOUT, "2000");
			secCfg.setSslAuthn(useClientCred);
			
			String url = server.getSecUrl()+"/servlet1";
			HttpClient client = HttpUtils.createClient(url, secCfg);
			GetMethod get = new GetMethod(url);
			client.executeMethod(get);
			String resp = get.getResponseBodyAsString();
			if (shouldBeOk)
				assertTrue("Got: " + resp, SimpleServlet.OK_GET.equals(resp));
			else
				fail("Should get an exception");

		} catch (Exception e)
		{
			if (!expected.isAssignableFrom(e.getClass()))
			{ 
				e.printStackTrace();
				fail("Should get OTHER exception");
			}
		} finally
		{
			server.stop();
		}
	}
	
	private JettyServer4Testing prepareServer(Properties p1) throws Exception
	{
		JettyServer4Testing server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		return server;
	}

	
	public void testSSLBio() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		p1.setProperty("j." + JettyProperties.USE_NIO, "false");
		JettyServer4Testing server = prepareServer(p1);
		makeRequest(server, true, null, true);
	}
	
	public void testSSLNio() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		p1.setProperty("j." + JettyProperties.USE_NIO, "true");
		JettyServer4Testing server = prepareServer(p1);
		makeRequest(server, true, null, true);
	}
	
	public void testGzip() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		p1.setProperty("j." + JettyProperties.ENABLE_GZIP, "true");
		p1.setProperty("j." + JettyProperties.MIN_GZIP_SIZE, "10");
		
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
	
	public void testDisabledCiphers() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		p1.setProperty("j." + JettyProperties.DISABLED_CIPHER_SUITES, allCiphers);
		p1.setProperty("j." + JettyProperties.USE_NIO, "false");
		JettyServer4Testing server = prepareServer(p1);
		makeRequest(server, false, SSLPeerUnverifiedException.class, true);

		p1.setProperty("j." + JettyProperties.USE_NIO, "true");
		server = prepareServer(p1);
		makeRequest(server, false, SSLPeerUnverifiedException.class, true);
	}
	
	public void testThreads() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		p1.setProperty("j." + JettyProperties.USE_NIO, "true");
		p1.setProperty("j." + JettyProperties.MAX_THREADS, "1");
		JettyServer4Testing server = prepareServer(p1);

		runThreadingCheck(server, 4000, 6000);
		
		p1.setProperty("j." + JettyProperties.MAX_THREADS, "2");
		server = prepareServer(p1);
		
		runThreadingCheck(server, 2000, 3500);
	}
	
	private void runThreadingCheck(JettyServer4Testing server, long minTime, long maxTime) throws Exception
	{
		HttpClient client = HttpUtils.createClient(new Properties());

		MethodRunner r1 = new MethodRunner(client, server.getUrl()+"/servlet1");
		MethodRunner r2 = new MethodRunner(client, server.getUrl()+"/servlet1");
		
		try
		{
			long start = System.currentTimeMillis();
			r1.start();
			r2.start();
			r1.join();
			r2.join();
			long end = System.currentTimeMillis();
			long time = end-start;
			System.out.println("Exec time: " + time);
			if (time < minTime || time > maxTime)
				fail("Execution was not timed out, took " + time);
		} finally
		{
			server.stop();
		}
	}
	
	private static class MethodRunner extends Thread
	{
		private String url;
		private HttpClient client;
		
		public MethodRunner(HttpClient client, String url)
		{
			this.client = client;
			this.url = url;
		}
		
		public void run()
		{
			PostMethod post = new PostMethod(url);
			post.addParameter("timeout", "2000");
			HttpUtils.setConnectionTimeout(client, 20000, 20000);
			try
			{
				client.executeMethod(post);
			} catch(Exception e)
			{
				e.printStackTrace();
				fail(e.toString());
			}
		}
	}
	
	
	public void testClientAuthn() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		p1.setProperty("j." + JettyProperties.WANT_CLIENT_AUTHN, "false");
		p1.setProperty("j." + JettyProperties.REQUIRE_CLIENT_AUTHN, "false");

		System.out.println("Authn want: NO require: NO");
		JettyServer4Testing server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, true);
		
		server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, false);
		
		p1.setProperty("j." + JettyProperties.WANT_CLIENT_AUTHN, "true");
		p1.setProperty("j." + JettyProperties.REQUIRE_CLIENT_AUTHN, "false");
		System.out.println("Authn want: YES require: NO");
		
		server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, true);
		
		server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, false);
		
		p1.setProperty("j." + JettyProperties.WANT_CLIENT_AUTHN, "true");
		p1.setProperty("j." + JettyProperties.REQUIRE_CLIENT_AUTHN, "true");
		System.out.println("Authn want: YES require: YES");
		
		server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, true);
		
		server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, false, SSLPeerUnverifiedException.class, false);
	}
	
	private static final String allCiphers = "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA " +
	"SSL_DH_DSS_WITH_DES_CBC_SHA " +
	"SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA " +
	"SSL_DH_RSA_WITH_DES_CBC_SHA " +
	"SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA " +
	"SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA " +
	"TLS_DHE_DSS_WITH_AES_128_CBC_SHA " +
	"TLS_DHE_DSS_WITH_AES_256_CBC_SHA " +
	"SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA " +
	"SSL_DHE_DSS_WITH_DES_CBC_SHA " +
	"SSL_DHE_DSS_WITH_RC4_128_SHA " +
	"SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA " +
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA " +
	"TLS_DHE_RSA_WITH_AES_256_CBC_SHA " +
	"SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA " +
	"SSL_DHE_RSA_WITH_DES_CBC_SHA " +
	"SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA " +
	"SSL_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA " +
	"SSL_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA " +
	"TLS_DH_anon_WITH_AES_128_CBC_SHA " +
	"TLS_DH_anon_WITH_AES_256_CBC_SHA " +
	"SSL_DH_anon_WITH_3DES_EDE_CBC_SHA " +
	"SSL_DH_anon_WITH_DES_CBC_SHA " +
	"SSL_DH_anon_WITH_RC4_128_MD5 " +
	"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA " +
	"SSL_DH_anon_EXPORT_WITH_RC4_40_MD5 " +
	"SSL_FORTEZZA_DMS_WITH_NULL_SHA " +
	"SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA " +
	"TLS_RSA_WITH_AES_128_CBC_SHA " +
	"TLS_RSA_WITH_AES_256_CBC_SHA " +
	"SSL_RSA_WITH_3DES_EDE_CBC_SHA " +
	"SSL_RSA_WITH_DES_CBC_SHA " +
	"SSL_RSA_WITH_IDEA_CBC_SHA " +
	"SSL_RSA_WITH_RC4_128_MD5 " +
	"SSL_RSA_WITH_RC4_128_SHA " +
	"SSL_RSA_WITH_NULL_MD5 " +
	"SSL_RSA_WITH_NULL_SHA " +
	"SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5 " +
	"SSL_RSA_EXPORT_WITH_RC4_40_MD5 " +
	"SSL_RSA_EXPORT_WITH_DES40_CBC_SHA " +
	"SSL_RSA_EXPORT1024_WITH_RC4_56_SHA " +
	"SSL_RSA_EXPORT1024_WITH_DES_CBC_SHA " +
	"SSL_RSA_FIPS_WITH_DES_CBC_SHA " +
	"SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA " +
	"TLS_KRB5_WITH_3DES_EDE_CBC_MD5 " +
	"TLS_KRB5_WITH_3DES_EDE_CBC_SHA " +
	"TLS_KRB5_WITH_DES_CBC_MD5 " +
	"TLS_KRB5_WITH_DES_CBC_SHA " +
	"TLS_KRB5_WITH_IDEA_CBC_SHA " +
	"TLS_KRB5_WITH_IDEA_CBC_MD5 " +
	"TLS_KRB5_WITH_RC4_128_MD5 " +
	"TLS_KRB5_WITH_RC4_128_SHA " +
	"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 " +
	"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA " +
	"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA " +
	"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 " +
	"TLS_KRB5_EXPORT_WITH_RC4_40_MD5 " +
	"TLS_KRB5_EXPORT_WITH_RC4_40_SHA " +
	"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA " +
	"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA " +
	"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA " +
	"TLS_ECDH_ECDSA_WITH_RC4_128_SHA " +
	"TLS_ECDH_ECDSA_WITH_NULL_SHA " +
	"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA " +
	"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA " +
	"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA " +
	"TLS_ECDH_RSA_WITH_RC4_128_SHA " +
	"TLS_ECDH_RSA_WITH_NULL_SHA " +
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA " +
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA " +
	"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA " +
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA " +
	"TLS_ECDHE_ECDSA_WITH_NULL_SHA " +
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA " +
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA " +
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA " +
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA " +
	"TLS_ECDHE_RSA_WITH_NULL_SHA " +
	"TLS_ECDH_anon_WITH_AES_128_CBC_SHA " +
	"TLS_ECDH_anon_WITH_AES_256_CBC_SHA " +
	"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA " +
	"TLS_ECDH_anon_WITH_RC4_128_SHA " +
	"TLS_ECDH_anon_WITH_NULL_SHA " +
	"TLS_EMPTY_RENEGOTIATION_INFO_SCSV ";
}

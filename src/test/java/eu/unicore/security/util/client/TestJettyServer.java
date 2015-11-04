/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.util.client;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Properties;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;

import junit.framework.TestCase;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.util.EntityUtils;

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
public class TestJettyServer extends TestCase
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
			HttpResponse response = client.execute(get);
			String resp = EntityUtils.toString(response.getEntity());
			if (shouldBeOk)
				assertTrue("Got: " + resp, SimpleServlet.OK_GET.equals(resp));
			else
				fail("Should get an exception");

		} catch (Exception e)
		{
			if (!expected.isAssignableFrom(e.getClass()))
			{ 
				e.printStackTrace();
				fail("Should get OTHER exception: "+expected.getName()+" got: "+e.getClass().getName());
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
		p1.setProperty("j." + HttpServerProperties.USE_NIO, "false");
		JettyServer4Testing server = prepareServer(p1);
		makeRequest(server, true, null, true);
	}
	
	public void testSSLNio() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		p1.setProperty("j." + HttpServerProperties.USE_NIO, "true");
		JettyServer4Testing server = prepareServer(p1);
		makeRequest(server, true, null, true);
	}
	
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
		p1.setProperty("j." + HttpServerProperties.USE_NIO, "false");
		JettyServer4Testing server = prepareServer(p1);
		makeRequest(server, false, SSLException.class, true);

		p1.setProperty("j." + HttpServerProperties.USE_NIO, "true");
		server = prepareServer(p1);
		makeRequest(server, false, SSLException.class, true);
	}

	public void testThreads() throws Exception
	{
		Properties p1 = JettyServer4Testing.getSecureProperties();
		p1.setProperty("j." + HttpServerProperties.USE_NIO, "true");
		p1.setProperty("j." + HttpServerProperties.MAX_THREADS, "1");
		JettyServer4Testing server = prepareServer(p1);

		runThreadingCheck(server, 4000, 6000);
		
		p1.setProperty("j." + HttpServerProperties.MAX_THREADS, "2");
		server = prepareServer(p1);
		
		runThreadingCheck(server, 2000, 3500);
	}

	private void runThreadingCheck(JettyServer4Testing server, long minTime, long maxTime) throws Exception
	{
		HttpClient client = HttpUtils.createClient(new HttpClientProperties(new Properties()));

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
			URI uri;
			try
			{
				uri = new URIBuilder(url).addParameter("timeout", "2000").build();
			} catch (URISyntaxException e1)
			{
				e1.printStackTrace();
				fail(e1.toString());
				return;
			}
			HttpPost post = new HttpPost(uri);
			HttpUtils.setConnectionTimeout(post, 20000, 20000);
			try
			{
				client.execute(post);
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
		p1.setProperty("j." + HttpServerProperties.WANT_CLIENT_AUTHN, "false");
		p1.setProperty("j." + HttpServerProperties.REQUIRE_CLIENT_AUTHN, "false");

		System.out.println("Authn want: NO require: NO");
		JettyServer4Testing server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, true);
		
		server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, false);
		
		p1.setProperty("j." + HttpServerProperties.WANT_CLIENT_AUTHN, "true");
		p1.setProperty("j." + HttpServerProperties.REQUIRE_CLIENT_AUTHN, "false");
		System.out.println("Authn want: YES require: NO");
		
		server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, true);
		
		server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, false);
		
		p1.setProperty("j." + HttpServerProperties.WANT_CLIENT_AUTHN, "true");
		p1.setProperty("j." + HttpServerProperties.REQUIRE_CLIENT_AUTHN, "true");
		System.out.println("Authn want: YES require: YES");
		
		server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, true, null, true);
		
		server = JettyServer4Testing.getInstance(p1, 65432, 1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.start();
		makeRequest(server, false, SSLException.class, false);
	}
}

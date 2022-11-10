/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 21-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.Properties;

import javax.net.ssl.SSLException;

import org.apache.hc.client5.http.ClientProtocolException;
import org.apache.hc.client5.http.RedirectException;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.impl.classic.BasicHttpClientResponseHandler;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.net.URIBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import eu.emi.security.authn.x509.X509CertChainValidatorExt;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.unicore.util.httpclient.DefaultClientConfiguration;
import eu.unicore.util.httpclient.HttpClientProperties;
import eu.unicore.util.httpclient.HttpUtils;
import eu.unicore.util.httpclient.IClientConfiguration;
import eu.unicore.util.httpclient.ServerHostnameCheckingMode;

public class TestHttpUtils
{
	private JettyServer4Testing server;
	
	@Before
	public void setUp() throws Exception
	{
		server = JettyServer4Testing.getInstance();
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.addServlet(RedirectServlet.class.getName(), "/servlet2");
		server.start();
	}
	
	@After
	public void tearDown() throws Exception
	{
		server.stop();
	}
	
	@Test
	public void testPlainHttp() throws Exception
	{
		HttpClient client = HttpUtils.createClient(new DefaultClientConfiguration().getHttpClientProperties());
		HttpGet get = new HttpGet(server.getUrl()+"/servlet1");
		String response = client.execute(get, new BasicHttpClientResponseHandler());
		assertTrue("Got: " + response, SimpleServlet.OK_GET.equals(response));
	}
	
	@Test
	public void testTimeouts() throws Exception
	{
		HttpClient client = HttpUtils.createClient(new DefaultClientConfiguration().getHttpClientProperties());
		URI uri = new URIBuilder(server.getUrl()+"/servlet1").
				addParameter("timeout", "5000").build();
		HttpPost post = new HttpPost(uri);
		HttpUtils.setConnectionTimeout(post, 300, 300);
		long start = System.currentTimeMillis();
		try
		{
			client.execute(post, new BasicHttpClientResponseHandler());
		} catch(SocketTimeoutException e)
		{
			long end = System.currentTimeMillis();
			System.out.println("Return after: " + (end-start));
			assertTrue("Execution was not timed out, took " + (end-start), 
					end-start < 600);
			return;
		}
		
		long end = System.currentTimeMillis();
		fail("Execution was not timed out, took " + (end-start));
	}

	@Test
	public void testRedirectSingle() throws Exception
	{
		URI uri = new URIBuilder(server.getUrl()+"/servlet2").
				addParameter("redirect-to", server.getUrl()+"/servlet1").build();
		HttpPost post = new HttpPost(uri);
		HttpClientProperties p = new HttpClientProperties(new Properties());
		p.setProperty(HttpClientProperties.HTTP_MAX_REDIRECTS, "1");
		HttpClient client = HttpUtils.createClient(p);
		String resp = client.execute(post, new BasicHttpClientResponseHandler());
		assertTrue("Got: " + resp, SimpleServlet.OK_GET.equals(resp));
	}

	@Test
	@Ignore("custom redirect handling currently not implemented")
	public void testRedirectsTooMany() throws Exception
	{
		HttpClientProperties p = new HttpClientProperties(new Properties());
		p.setProperty(HttpClientProperties.HTTP_MAX_REDIRECTS, "5");
		p.setProperty(HttpClientProperties.ALLOW_CIRCULAR_REDIRECTS, "true");
		HttpClient client = HttpUtils.createClient(p);
		URI uri = new URIBuilder(server.getUrl()+"/servlet2")
				.addParameter("redirect-to", server.getUrl()+"/servlet1")
				.addParameter("redirect-to-first", server.getUrl()+"/servlet2")
				.addParameter("num", "6").build();
		HttpPost post = new HttpPost(uri);
		
		try
		{
			client.execute(post, new BasicHttpClientResponseHandler());
			fail("Got proper response when redirects limit should be hit");
		} catch(ClientProtocolException e)
		{
			assertTrue("Got wrong exception cause: " + e, e.getCause() instanceof RedirectException);
		}
	}

	@Test
	@Ignore("custom redirect handling currently not implemented")
	public void testRedirectsMany() throws Exception
	{
		HttpClientProperties p = new HttpClientProperties(new Properties());
		p.setProperty(HttpClientProperties.HTTP_MAX_REDIRECTS, "5");
		p.setProperty(HttpClientProperties.ALLOW_CIRCULAR_REDIRECTS, "true");
		HttpClient client = HttpUtils.createClient(p);
		URI uri = new URIBuilder(server.getUrl()+"/servlet2")
				.addParameter("redirect-to", server.getUrl()+"/servlet1")
				.addParameter("redirect-to-first", server.getUrl()+"/servlet2")
				.addParameter("num", "4").build();
		HttpPost post = new HttpPost(uri);
		String resp = client.execute(post, new BasicHttpClientResponseHandler());
		assertTrue("Got: " + resp, SimpleServlet.OK_POST.equals(resp));
	}
	
	@Test
	public void testHttps() throws Exception
	{
		X509Credential cred = new KeystoreCredential("src/test/resources/client/httpclient.jks",
			"the!client".toCharArray(), "the!client".toCharArray(), null, "JKS");
		X509CertChainValidatorExt validator = new KeystoreCertChainValidator("src/test/resources/client/httpclient.jks",
			"the!client".toCharArray(), "JKS", -1);
		IClientConfiguration secCfg = new DefaultClientConfiguration(validator, cred);
		
		String url = server.getSecUrl()+"/servlet1";
		HttpClient client = HttpUtils.createClient(url, secCfg);
		HttpGet get = new HttpGet(url);
		String resp = client.execute(get, new BasicHttpClientResponseHandler());
		assertTrue("Got: " + resp, SimpleServlet.OK_GET.equals(resp));
	}

	@Test
	public void testHttpsWithGoogle() throws Exception
	{
		String defaultTS = System.getProperty("java.home") + "/lib/security/cacerts";
		X509CertChainValidatorExt validator = new KeystoreCertChainValidator(
				defaultTS, "changeit".toCharArray(), "JKS", -1);
		DefaultClientConfiguration secCfg = new DefaultClientConfiguration();
		secCfg.setValidator(validator);
		secCfg.setSslEnabled(true);
		
		String url = "https://google.com";
		HttpClient client = HttpUtils.createClient(url, secCfg);
		HttpGet get = new HttpGet(url);
		ClassicHttpResponse resp = client.executeOpen(null, get, null);
		assertTrue("Got: " + resp, HttpStatus.SC_OK == resp.getCode());
		EntityUtils.consumeQuietly(resp.getEntity());
		resp.close();
	}
	
	@Test
	public void testHttpsInvalidClient() throws Exception
	{
		X509Credential cred = new KeystoreCredential("src/test/resources/client/combined.jks",
			"the!client".toCharArray(), "the!client".toCharArray(), "mykey", "JKS");
		X509CertChainValidatorExt validator = new KeystoreCertChainValidator("src/test/resources/client/combined.jks",
			"the!client".toCharArray(), "JKS", -1);
		IClientConfiguration secCfg = new DefaultClientConfiguration(validator, cred);
		
		String url = server.getSecUrl()+"/servlet1";
		
		HttpClient client = HttpUtils.createClient(url, secCfg);

		HttpGet get = new HttpGet(url);
		try
		{
			client.execute(get, new BasicHttpClientResponseHandler());
			fail("Managed to connect with untrusted certificate!!!!!");
		} catch (SSLException e)
		{
			//OK
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.toString());
		}
	}
	
	/*
	public void testSSLHostnameCheckingLoop() throws Exception
	{
		for (int i=0; i<100; i++)
			testSSLHostnameChecking();
	}
	*/
	
	@Test
	public void testSSLHostnameChecking() throws Exception
	{
		X509Credential cred = new KeystoreCredential("src/test/resources/client/httpclient.jks",
				"the!client".toCharArray(), "the!client".toCharArray(), null, "JKS");
		X509CertChainValidatorExt validator = new KeystoreCertChainValidator("src/test/resources/client/httpclient.jks",
				"the!client".toCharArray(), "JKS", -1);
		DefaultClientConfiguration secCfg = new DefaultClientConfiguration(validator, cred);
		String url = server.getSecUrl()+"/servlet1";
		
		
		try
		{
			performRequest(url, secCfg, ServerHostnameCheckingMode.FAIL);
			fail("Managed to make a connection to a server " +
					"with cert subject different from its address");
		} catch (SocketException e)
		{
			//expected
		} catch (SSLException e)
		{
			//also possible
		} catch (Exception e)
		{
			e.printStackTrace();
			fail("Got wrong exception: " + e);
		}
		
		performRequest(url, secCfg, ServerHostnameCheckingMode.WARN);

		performRequest(url, secCfg, ServerHostnameCheckingMode.NONE);
	}
	
	private void performRequest(String url, DefaultClientConfiguration secCfg, 
			ServerHostnameCheckingMode mode) throws Exception
	{
		secCfg.setServerHostnameCheckingMode(mode);
		HttpClient client = HttpUtils.createClient(url, secCfg);
		HttpGet get = new HttpGet(url);
		client.execute(get, new BasicHttpClientResponseHandler());
	}
}

/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 21-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.util.Properties;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.RedirectException;
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
import eu.unicore.util.httpclient.IClientConfiguration;
import eu.unicore.util.httpclient.ServerHostnameCheckingMode;

import junit.framework.TestCase;

public class TestHttpUtils extends TestCase
{
	private JettyServer4Testing server;
	
	public void setUp() throws Exception
	{
		server = JettyServer4Testing.getInstance(1);
		server.addServlet(SimpleServlet.class.getName(), "/servlet1");
		server.addServlet(RedirectServlet.class.getName(), "/servlet2");
		server.start();
	}
	
	public void tearDown() throws Exception
	{
		server.stop();
	}
	
	public void testPlainHttp() throws Exception
	{
		HttpClient client = HttpUtils.createClient(new DefaultClientConfiguration().getHttpClientProperties());
		HttpGet get = new HttpGet(server.getUrl()+"/servlet1");
		HttpResponse response = client.execute(get);
		String resp = EntityUtils.toString(response.getEntity());
		assertTrue("Got: " + resp, SimpleServlet.OK_GET.equals(resp));
	}
	
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
			client.execute(post);
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

	public void testRedirectSingle() throws Exception
	{
		URI uri = new URIBuilder(server.getUrl()+"/servlet2").
				addParameter("redirect-to", server.getUrl()+"/servlet1").build();
		HttpPost post = new HttpPost(uri);
		HttpClientProperties p = new HttpClientProperties(new Properties());
		p.setProperty(HttpClientProperties.HTTP_MAX_REDIRECTS, "1");
		HttpClient client = HttpUtils.createClient(p);
		HttpResponse response = client.execute(post);
		String resp = EntityUtils.toString(response.getEntity());
		assertTrue("Got: " + resp, SimpleServlet.OK_POST.equals(resp));
	}

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
			client.execute(post);
			fail("Got proper response when redirects limit should be hit");
		} catch(ClientProtocolException e)
		{
			assertTrue("Got wrong exception cause: " + e, e.getCause() instanceof RedirectException);
		}
	}

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
		
		HttpResponse response = client.execute(post);
		String resp = EntityUtils.toString(response.getEntity());
		assertTrue("Got: " + resp, SimpleServlet.OK_POST.equals(resp));
	}
	
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
		HttpResponse response = client.execute(get);
		String resp = EntityUtils.toString(response.getEntity());
		assertTrue("Got: " + resp, SimpleServlet.OK_GET.equals(resp));
	}

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
			client.execute(get);
			fail("Managed to conenct with untrusted certificate!!!!!");
		} catch (Exception e)
		{
			//OK
		}
	}
	
	/*
	public void testSSLHostnameCheckingLoop() throws Exception
	{
		for (int i=0; i<100; i++)
			testSSLHostnameChecking();
	}
	*/
	
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
		HttpResponse response = client.execute(get);
		EntityUtils.toString(response.getEntity());
	}
}

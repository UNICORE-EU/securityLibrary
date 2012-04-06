/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 21-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import java.net.SocketTimeoutException;
import java.util.Properties;

import javax.net.ssl.SSLHandshakeException;

import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;

import junit.framework.TestCase;

public class TestHttpUtils extends TestCase
{
	private TestJettyServer server;
	
	public void setUp() throws Exception
	{
		server = TestJettyServer.getInstance(1);
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
		HttpClient client = HttpUtils.createClient(new Properties());
		GetMethod get = new GetMethod(server.getUrl()+"/servlet1");
		client.executeMethod(get);
		String resp = get.getResponseBodyAsString();
		assertTrue("Got: " + resp, SimpleServlet.OK_GET.equals(resp));
	}
	
	public void testTimeouts() throws Exception
	{
		HttpClient client = HttpUtils.createClient(new Properties());
		PostMethod post = new PostMethod(server.getUrl()+"/servlet1");
		post.addParameter("timeout", "5000");
		HttpUtils.setConnectionTimeout(client, 300, 300);
		long start = System.currentTimeMillis();
		try
		{
			client.executeMethod(post);
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

	public void testRedirects() throws Exception
	{
		
		PostMethod post = new PostMethod(server.getUrl()+"/servlet2");
		post.addParameter("redirect-to", server.getUrl()+"/servlet1");
		Properties p = new Properties();
		p.setProperty(HttpUtils.HTTP_MAX_REDIRECTS, "1");
		HttpClient client = HttpUtils.createClient(p);
		client.executeMethod(post);
		String resp = post.getResponseBodyAsString();
		assertTrue("Got: " + resp, SimpleServlet.OK_POST.equals(resp));
		
		p.setProperty(HttpUtils.HTTP_MAX_REDIRECTS, "5");
		client = HttpUtils.createClient(p);
		post = new PostMethod(server.getUrl()+"/servlet2");
		post.addParameter("redirect-to", server.getUrl()+"/servlet1");
		post.addParameter("redirect-to-first", server.getUrl()+"/servlet2");
		post.addParameter("num", "6");
		client.executeMethod(post);
		
		System.out.println(post.getStatusCode() + " " + post.getStatusLine());
		resp = post.getResponseBodyAsString();
		assertTrue("Got: " + post.getStatusCode(), post.getStatusCode() == 302);
	}
	
	public void testHttps() throws Exception
	{
		X509Credential cred = new KeystoreCredential("src/test/resources/client/httpclient.jks",
			"the!client".toCharArray(), "the!client".toCharArray(), null, "JKS");
		X509CertChainValidator validator = new KeystoreCertChainValidator("src/test/resources/client/httpclient.jks",
			"the!client".toCharArray(), "JKS", -1);
		IAuthenticationConfiguration secCfg = new DefaultAuthnConfigurationImpl(validator, cred);
		
		String url = server.getSecUrl()+"/servlet1";
		HttpClient client = HttpUtils.createClient(url, secCfg, new Properties());
		GetMethod get = new GetMethod(url);
		client.executeMethod(get);
		String resp = get.getResponseBodyAsString();
		assertTrue("Got: " + resp, SimpleServlet.OK_GET.equals(resp));
	}

	public void testHttpsInvalidClient() throws Exception
	{
		X509Credential cred = new KeystoreCredential("src/test/resources/client/combined.jks",
			"the!client".toCharArray(), "the!client".toCharArray(), "mykey", "JKS");
		X509CertChainValidator validator = new KeystoreCertChainValidator("src/test/resources/client/combined.jks",
			"the!client".toCharArray(), "JKS", -1);
		IAuthenticationConfiguration secCfg = new DefaultAuthnConfigurationImpl(validator, cred);
		
		String url = server.getSecUrl()+"/servlet1";
		
		HttpClient client = HttpUtils.createClient(url, secCfg, new Properties());
		client.getParams().setParameter(HttpMethodParams.RETRY_HANDLER, 
			new DefaultHttpMethodRetryHandler(0, false));

		GetMethod get = new GetMethod(url);
		try
		{
			client.executeMethod(get);
			fail("Managed to conenct with untrusted certificate!!!!!");
		} catch (SSLHandshakeException e)
		{
			//OK
		} catch (Exception e)
		{
			e.printStackTrace();
			fail(e.toString());
		}
	}
}

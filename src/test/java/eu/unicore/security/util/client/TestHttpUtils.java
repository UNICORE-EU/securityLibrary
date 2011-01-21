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

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;

import junit.framework.TestCase;

public class TestHttpUtils extends TestCase
{
	private JettyServer server;
	
	public void setUp() throws Exception
	{
		server = new JettyServer(-1);
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
		IAuthenticationConfiguration secCfg = new SimpleAuthnConfigurationImpl()
		{
			public boolean doSSLAuthn()
			{
				return true;
			}
			public String getKeystore()
			{
				return getTruststore();
			}
			public String getKeystoreAlias()
			{
				return null;
			}
			public String getKeystoreKeyPassword()
			{
				return getTruststorePassword();
			}
			public String getKeystorePassword()
			{
				return getTruststorePassword();
			}
			public String getKeystoreType()
			{
				return "JKS";
			}
			public String getTruststore()
			{
				return "src/test/resources/client/httpclient.jks";
			}
			public String getTruststorePassword()
			{
				return "the!client";
			}
			public String getTruststoreType()
			{
				return "JKS";
			}
		};
		
		String url = server.getSecUrl()+"/servlet1";
		HttpClient client = HttpUtils.createClient(url, secCfg, new Properties());
		GetMethod get = new GetMethod(url);
		client.executeMethod(get);
		String resp = get.getResponseBodyAsString();
		assertTrue("Got: " + resp, SimpleServlet.OK_GET.equals(resp));
	}

}

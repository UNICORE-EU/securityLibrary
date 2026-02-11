package eu.unicore.util.httpclient;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

/**
 * Empty hostname verifier - we don't use this functionality for Apache 
 * HTTP client as the functionality is already provided on the socket creation.
 */
public class EmptyHostnameVerifier implements HostnameVerifier
{
	@Override
	public boolean verify(String hostname, SSLSession session)
	{
		return true;
	}
}

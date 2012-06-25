/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.httpclient;

import java.io.IOException;

import javax.net.ssl.SSLPeerUnverifiedException;

import org.apache.commons.httpclient.DefaultHttpMethodRetryHandler;
import org.apache.commons.httpclient.HttpMethod;

/**
 * Extension of the {@link DefaultHttpMethodRetryHandler} which doesn't retry requests also in case of 
 * {@link SSLPeerUnverifiedException}
 * @author K. Benedyczak
 */
public class RetryHandler extends DefaultHttpMethodRetryHandler
{
	public boolean retryMethod(final HttpMethod method, final IOException exception,
			int executionCount)
	{
		if (exception instanceof SSLPeerUnverifiedException)
			return false;
		return super.retryMethod(method, exception, executionCount);
	}
}

/*
 * Copyright (c) 2013 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.httpclient;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.ProtocolException;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpHead;
import org.apache.http.client.methods.HttpOptions;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpTrace;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.LaxRedirectStrategy;
import org.apache.http.protocol.HttpContext;

/**
 * As {@link LaxRedirectStrategy} but additionally redirects POST in case of 301 and 302 responses
 * as POST, not as GET (the {@link LaxRedirectStrategy} redirects POST as POST only in the case of 307).
 * <p>
 * This code is heavily based on the {@link DefaultRedirectStrategy}.
 * @author K. Benedyczak
 */
public class VeryLaxRedirectStrategy extends LaxRedirectStrategy
{
	public HttpUriRequest getRedirect(final HttpRequest request, final HttpResponse response,
			final HttpContext context) throws ProtocolException
	{
		URI uri = getLocationURI(request, response, context);
		String method = request.getRequestLine().getMethod();
		if (method.equalsIgnoreCase(HttpHead.METHOD_NAME))
		{
			return new HttpHead(uri);
		} else if (method.equalsIgnoreCase(HttpGet.METHOD_NAME))
		{
			return new HttpGet(uri);
		} else
		{
			int status = response.getStatusLine().getStatusCode();
			if (status == HttpStatus.SC_TEMPORARY_REDIRECT || status == HttpStatus.SC_MOVED_PERMANENTLY
					|| status == HttpStatus.SC_MOVED_TEMPORARILY)
			{
				if (method.equalsIgnoreCase(HttpPost.METHOD_NAME))
				{
					return copyEntity(new HttpPost(uri), request);
				} else if (method.equalsIgnoreCase(HttpPut.METHOD_NAME))
				{
					return copyEntity(new HttpPut(uri), request);
				} else if (method.equalsIgnoreCase(HttpDelete.METHOD_NAME))
				{
					return new HttpDelete(uri);
				} else if (method.equalsIgnoreCase(HttpTrace.METHOD_NAME))
				{
					return new HttpTrace(uri);
				} else if (method.equalsIgnoreCase(HttpOptions.METHOD_NAME))
				{
					return new HttpOptions(uri);
				} else if (method.equalsIgnoreCase(HttpPatch.METHOD_NAME))
				{
					return copyEntity(new HttpPatch(uri), request);
				}
			}
			return new HttpGet(uri);
		}
	}

	private HttpUriRequest copyEntity(final HttpEntityEnclosingRequestBase redirect,
			final HttpRequest original)
	{
		if (original instanceof HttpEntityEnclosingRequest)
		{
			redirect.setEntity(((HttpEntityEnclosingRequest) original).getEntity());
		}
		return redirect;
	}

	public URI getLocationURI(final HttpRequest request, final HttpResponse response,
			final HttpContext context) throws ProtocolException
	{
		URI ret = super.getLocationURI(request, response, context);
		
		try
		{
			URIBuilder builder = new URIBuilder(request.getRequestLine().getUri());
			List<NameValuePair> origParams = builder.getQueryParams();
			URIBuilder retBuilder = new URIBuilder(ret);
			for (NameValuePair param: origParams)
				retBuilder.addParameter(param.getName(), param.getValue());
			return retBuilder.build();
		} catch (URISyntaxException e)
		{
			throw new IllegalStateException("Can not parse the original request URI when " +
					"trying to establish redirect address", e);
		}
	}

}

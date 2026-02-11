package eu.unicore.util.httpclient;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.channels.SocketChannel;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.SchemePortResolver;
import org.apache.hc.client5.http.auth.AuthCache;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.CredentialsStore;
import org.apache.hc.client5.http.auth.UsernamePasswordCredentials;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.DefaultRedirectStrategy;
import org.apache.hc.client5.http.impl.auth.BasicAuthCache;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.auth.BasicScheme;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.io.DefaultHttpClientConnectionOperator;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.DetachedSocketFactory;
import org.apache.hc.client5.http.io.HttpClientConnectionOperator;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.URIScheme;
import org.apache.hc.core5.http.config.Lookup;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.logging.log4j.Logger;

import eu.emi.security.authn.x509.X509Credential;
import eu.unicore.security.canl.SSLContextCreator;
import eu.unicore.util.Log;

/**
 * Contains helper code to create HttpClient instances. The following settings are always set
 * (depending on configuration passed in {@link Properties} object:
 * <ul>
 *  <li> maximum redirects which are automatically taken,
 *  <li> whether to set Connection: close HTTP header
 *  <li> {@link PoolingHttpClientConnectionManager} is used with a preconfigured default 
 *  values of max connection attempts. 
 *  <li> user agent is set to Mozilla/4.0.
 * </ul>
 * <p>
 * Additionally one can use additional methods of this class to:
 * <ul>
 *  <li> configure connection's SSL
 *  <li> add support for HTTP proxy
 * </ul>
 * The returned client can be configured further by using standard {@link HttpClient}
 * parameters API. Note that for convenience many parameters can be set using the {@link HttpClientProperties}.
 * <p>
 * Contains some code from XFire's CommonsHttpMessageSender
 * 
 * @author schuller
 * @author golbi
 * @author <a href="mailto:dan@envoisolutions.com">Dan Diephouse</a>
 * @author <a href="mailto:tsztelak@gmail.com">Tomasz Sztelak</a>
 */
public class HttpUtils {

	private static final Logger logger = Log.getLogger(Log.CLIENT, HttpUtils.class);

	private static final ConnectionCloseInterceptor CONN_CLOSE_INTERCEPTOR = new ConnectionCloseInterceptor();

	public static final String USER_AGENT = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)";

	/**
	 * Convenience method for getting a {@link HttpClient} configured 
	 * with HTTP proxy support and SSL setup. Whenever possible use this method.
	 * @param uri -  URI to connect to
	 * @param security - Security settings. Note that SSL can be turned off there.
	 * @return a preconfigured http client
	 */
	public static synchronized HttpClient createClient(String uri, IClientConfiguration security)
	{
		PoolingHttpClientConnectionManager connMan = security.isSslEnabled() ? 
				getSSLConnectionManager(security) : new PoolingHttpClientConnectionManager();
		HttpClientBuilder clientBuilder = createClientBuilder(security.getHttpClientProperties(), connMan);
		configureProxy(clientBuilder, uri, security.getHttpClientProperties());
		return clientBuilder.build();
	}

	/**
	 * Create a HTTP client.
	 * The returned client has neither SSL nor HTTP proxy support configured.
	 */
	public static synchronized HttpClient createClient(HttpClientProperties properties)
	{
		return createClientBuilder(properties, new PoolingHttpClientConnectionManager()).build();
	}

	/**
	 * Create a HTTP client builder
	 * The returned client has no HTTP proxy support configured.
	 */
	public static synchronized HttpClientBuilder createClientBuilder(HttpClientProperties properties,
			PoolingHttpClientConnectionManager connMan)
	{
		boolean connClose = properties.getBooleanValue(HttpClientProperties.CONNECTION_CLOSE);
		boolean allowCircularRedirects = properties.getBooleanValue(
				HttpClientProperties.ALLOW_CIRCULAR_REDIRECTS);
		int maxRedirects = properties.getIntValue(HttpClientProperties.HTTP_MAX_REDIRECTS);
		boolean allowRedirects = maxRedirects > 0;

		int maxConnPerHost = properties.getIntValue(HttpClientProperties.MAX_HOST_CONNECTIONS);
		connMan.setDefaultMaxPerRoute(maxConnPerHost);
		int maxTotalConn  = properties.getIntValue(HttpClientProperties.MAX_TOTAL_CONNECTIONS);
		connMan.setMaxTotal(maxTotalConn);

		HttpClientBuilder clientBuilder = HttpClientBuilder.create();
		clientBuilder.setConnectionManager(connMan);
		clientBuilder.setRedirectStrategy(new DefaultRedirectStrategy());
		RequestConfig.Builder requestConfigBuilder = RequestConfig.custom();
		int socketTimeout = properties.getIntValue(HttpClientProperties.SO_TIMEOUT);
		int connectTimeout = properties.getIntValue(HttpClientProperties.CONNECT_TIMEOUT);

		setConnectionTimeout(requestConfigBuilder, socketTimeout, connectTimeout);
		RequestConfig requestConfig = requestConfigBuilder.
				setCircularRedirectsAllowed(allowCircularRedirects).
				setMaxRedirects(maxRedirects).
				setRedirectsEnabled(allowRedirects).
				build();
		clientBuilder.setDefaultRequestConfig(requestConfig);
		clientBuilder.setUserAgent(USER_AGENT);
		if (connClose) {
			clientBuilder.addRequestInterceptorFirst(CONN_CLOSE_INTERCEPTOR);
		}
		return clientBuilder;
	}

	private static final DetachedSocketFactory SELECTABLE_SOCKET_FACTORY = socksProxy -> {
		if(socksProxy==null) {
			return SocketChannel.open().socket(); 
		}
		else {
			return new Socket(socksProxy);
		}
	};
	
	private static DefaultHttpClientConnectionOperator selectableSocketConnections(SchemePortResolver schemes,
            DnsResolver dns, Lookup<TlsSocketStrategy> tls)
	{
		return new DefaultHttpClientConnectionOperator(SELECTABLE_SOCKET_FACTORY, schemes, dns, tls);
	}

	public static PoolingHttpClientConnectionManager getSSLConnectionManager(IClientConfiguration security)
	{
		PoolingHttpClientConnectionManagerBuilder b = new PoolingHttpClientConnectionManagerBuilder(){
			@Override
		    protected HttpClientConnectionOperator createConnectionOperator(SchemePortResolver schemes, DnsResolver dns, TlsSocketStrategy tls)
			{
				Lookup<TlsSocketStrategy> l = RegistryBuilder.<TlsSocketStrategy>create()
                        .register(URIScheme.HTTPS.id, tls).build();
				return selectableSocketConnections(schemes, dns, l);
			}
		};
		SSLContext sslContext = createSSLContext(security);
		HostnameVerifier hostnameVerifier = new EmptyHostnameVerifier();
		DefaultClientTlsStrategy tls = new DefaultClientTlsStrategy(sslContext, hostnameVerifier);
		b.setTlsSocketStrategy(tls);
		return b.build();
	}

	/**
	 * configure the HTTP proxy settings on the given client
	 * 
	 * @param clientBuilder - the HttpClientBuilder instance
	 * @param uri - the URI to connect to
	 * @param properties
	 */
	public static void configureProxy(HttpClientBuilder clientBuilder, String uri, HttpClientProperties properties){
		if (isNonProxyHost(uri, properties)) 
			return;

		// Setup the proxy settings
		String proxyHost = properties.getValue(HttpClientProperties.HTTP_PROXY_HOST);
		if (proxyHost == null)
		{
			proxyHost = System.getProperty(HttpClientProperties.HTTP_PROXY_HOST);
		}

		if (proxyHost != null && proxyHost.trim().length()>0)
		{ 
			Integer port = properties.getIntValue(HttpClientProperties.HTTP_PROXY_PORT);
			if (port == null)
			{
				String portS = System.getProperty(HttpClientProperties.HTTP_PROXY_PORT);
				if (portS != null)
					port = Integer.parseInt(portS);
			}
			if (port == null)
				port = 80;
			HttpHost proxy = new HttpHost(proxyHost, port);
			clientBuilder.setProxy(proxy);
			String proxyUser = properties.getValue(HttpClientProperties.HTTP_PROXY_USER);
			String proxyPass = properties.getValue(HttpClientProperties.HTTP_PROXY_PASS);
			if (proxyUser != null && proxyPass != null)
			{
				Credentials credentials = getCredentials(proxyUser, proxyPass);
				CredentialsStore credentialsProvider = new BasicCredentialsProvider();
				credentialsProvider.setCredentials(new AuthScope(proxyHost, port), 
						credentials);
				clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
				clientBuilder.addRequestInterceptorLast(new ProxyPreemptiveAuthnInterceptor(proxy));
			}
		}
	}

	private static boolean isNonProxyHost(String uri, HttpClientProperties properties){
		String nonProxyHosts = properties.getValue(HttpClientProperties.HTTP_NON_PROXY_HOSTS);
		if(nonProxyHosts==null)return false;
		try{
			URI u=new URI(uri);
			String host=u.getHost();
			String[] npHosts=nonProxyHosts.split(" ");
			for(String npHost: npHosts){
				if(host.contains(npHost))return true;
			}
		}catch(URISyntaxException e){
			logger.error("Can't resolve URI from "+uri, e);
		}	
		return false;
	}

	private static Credentials getCredentials(String username, String password){
		int domainIndex = username.indexOf('\\');
		if (domainIndex > 0 && username.length() > domainIndex + 1) {
			throw new RuntimeException("Domain credentials not supported.");
		} 
		return new UsernamePasswordCredentials(username, password.toCharArray());
	}

	private static void setConnectionTimeout(RequestConfig.Builder reqConfigBuilder, 
			int socketTimeout, int connectTimeout) {
		reqConfigBuilder.setResponseTimeout(socketTimeout, TimeUnit.MILLISECONDS);
		reqConfigBuilder.setConnectionRequestTimeout(connectTimeout, TimeUnit.MILLISECONDS);
	}

	/**
	 * Helper method: sets the connection timeout for the HTTP client and the socket timeout.
	 * @param request http request to be configured
	 * @param socketTimeout socket timeout in milliseconds
	 * @param connectTimeout connection timeout in milliseconds
	 */
	public static void setConnectionTimeout(HttpUriRequestBase request, 
			int socketTimeout, int connectTimeout) {
		RequestConfig current = request.getConfig();
		RequestConfig.Builder reqConfigBuilder = current != null ? 
				RequestConfig.copy(current) : RequestConfig.custom();
		setConnectionTimeout(reqConfigBuilder, socketTimeout, connectTimeout);
		request.setConfig(reqConfigBuilder.build());
	}

	/**
	 * Adds the 'Connection: close' HTTP header.
	 * @author K. Benedyczak
	 */
	private static class ConnectionCloseInterceptor implements HttpRequestInterceptor
	{
		@Override
		public void process(HttpRequest request, EntityDetails details, HttpContext context) throws HttpException,
				IOException
		{
			request.setHeader("Connection", "close");
		}
	}
	
	/**
	 * Makes the authentication preemptive, i.e. the client sends the authn response with the first request,
	 * without even receiving a challenge. This is very dangerous in general, we use it only in the case of HTTP
	 * proxy authn as it may degrade performance otherwise.
	 * @author K. Benedyczak
	 */
	private static class ProxyPreemptiveAuthnInterceptor implements HttpRequestInterceptor
	{
		private HttpHost host;

		public ProxyPreemptiveAuthnInterceptor(HttpHost host)
		{
			this.host = host;
		}

		@Override
		public void process(HttpRequest request, EntityDetails details, HttpContext context) throws HttpException,
				IOException
		{
			HttpClientContext clientContext = (HttpClientContext)context;
			AuthCache authCache = clientContext.getAuthCache();
			if (authCache == null)
			{
				authCache = new BasicAuthCache();
				clientContext.setAuthCache(authCache);				
			}
			if (authCache.get(host) == null)
			{
				authCache.put(host, new BasicScheme());
			}
		}
	}

	public static SSLContext createSSLContext(IPlainClientConfiguration sec)
	{
		X509Credential credential = sec.doSSLAuthn() ? sec.getCredential() : null;
		try
		{
			SSLContext sslContext = SSLContextCreator.createSSLContext(credential, sec.getValidator(), 
					"TLS", "HTTP Client", logger, sec.getServerHostnameCheckingMode());
			return sslContext;
		} catch (Exception e)
		{
			throw new RuntimeException(e);
		}
	}
}

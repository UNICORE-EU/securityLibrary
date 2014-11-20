package eu.unicore.util.httpclient;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Properties;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.auth.AuthScheme;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.NTCredentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.auth.NTLMSchemeFactory;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.protocol.HttpContext;
import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.X509Credential;
import eu.unicore.security.canl.SSLContextCreator;
import eu.unicore.util.Log;

/**
 * Contains helper code to create HttpClient instances. The following settings are always set
 * (depending on configuration passed in {@link Properties} object:
 * <ul>
 *  <li> maximum redirects which are automatically taken,
 *  <li> whether to set Connection: close HTTP header
 *  <li> {@link MultiThreadedHttpConnectionManager} is used with a preconfigured default 
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
 * Contains some code from XFire's {@link CommonsHttpMessageSender}
 * 
 * @author schuller
 * @author golbi
 * @author <a href="mailto:dan@envoisolutions.com">Dan Diephouse</a>
 * @author <a href="mailto:tsztelak@gmail.com">Tomasz Sztelak</a>
 */
public class HttpUtils {

	private static final Logger logger=Log.getLogger(Log.CLIENT, HttpUtils.class);
	private static final ConnectionCloseInterceptor CONN_CLOSE_INTERCEPTOR = new ConnectionCloseInterceptor();

	//prevent instantiation 
	private HttpUtils(){}
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
		@SuppressWarnings("resource")
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
	 * Create a HTTP client.
	 * The returned client has no HTTP proxy support configured.
	 */
	private static synchronized HttpClientBuilder createClientBuilder(HttpClientProperties properties,
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
		clientBuilder.setRedirectStrategy(new VeryLaxRedirectStrategy());

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
		if (connClose)
			clientBuilder.addInterceptorFirst(CONN_CLOSE_INTERCEPTOR);
		return clientBuilder;
	}

	public static PoolingHttpClientConnectionManager getSSLConnectionManager(IClientConfiguration security)
	{
		SSLContext sslContext = createSSLContext(security);
		CanlHostnameVerifier hostnameVerifier = new CanlHostnameVerifier(
				security.getServerHostnameCheckingMode());
		int connectTimeout = security.getHttpClientProperties().
				getIntValue(HttpClientProperties.CONNECT_TIMEOUT);
		SSLConnectionSocketFactory sslsf = new CustomSSLConnectionSocketFactory(sslContext, hostnameVerifier,
				connectTimeout);
		PlainConnectionSocketFactory plainsf = new PlainConnectionSocketFactory();
		
		Registry<ConnectionSocketFactory> r = RegistryBuilder.<ConnectionSocketFactory>create()
		        .register("http", plainsf)
		        .register("https", sslsf)
		        .build();

		return new PoolingHttpClientConnectionManager(r);
	}
	
	/**
	 * configure the HTTP proxy settings on the given client
	 * 
	 * @param client - the HttpClient instance
	 * @param uri - the URI to connect to
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
				boolean ntlm = credentials instanceof NTCredentials;

				CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
				credentialsProvider.setCredentials(new AuthScope(proxyHost, port), 
						credentials);
				clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
				clientBuilder.addInterceptorLast(new ProxyPreemptiveAuthnInterceptor(proxy, ntlm));
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
			return new NTCredentials(
					username.substring(0, domainIndex), 
					password, 
					"localhost", 
					username.substring(domainIndex+1));
		} 
		return new UsernamePasswordCredentials(username, password);
	}

	private static void setConnectionTimeout(RequestConfig.Builder reqConfigBuilder, 
			int socketTimeout, int connectTimeout) {
		reqConfigBuilder.setSocketTimeout(socketTimeout);
		reqConfigBuilder.setConnectTimeout(connectTimeout);
		reqConfigBuilder.setConnectionRequestTimeout(connectTimeout);
	}

	/**
	 * Helper method: sets the connection timeout for the HTTP client and the socket timeout.
	 * @param request http request to be configured
	 * @param socketTimeout socket timeout in milliseconds
	 * @param connectTimeout connection timeout in milliseconds
	 */
	public static void setConnectionTimeout(HttpRequestBase request, 
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
		public void process(HttpRequest request, HttpContext context) throws HttpException,
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
		private boolean ntlm;
		
		public ProxyPreemptiveAuthnInterceptor(HttpHost host, boolean ntlm)
		{
			this.host = host;
			this.ntlm = ntlm;
		}

		@Override
		public void process(HttpRequest request, HttpContext context) throws HttpException,
				IOException
		{
			AuthCache authCache = (AuthCache) context.getAttribute(HttpClientContext.AUTH_CACHE);
			if (authCache == null)
			{
				authCache = new BasicAuthCache();
				context.setAttribute(HttpClientContext.AUTH_CACHE, authCache);				
			}
			
			if (authCache.get(host) == null)
			{
				AuthScheme scheme = ntlm ? new NTLMSchemeFactory().newInstance(null):
					new BasicScheme();
				authCache.put(host, scheme);
			}
		}
	}
	

	static String[] protocols = {"TLSv1","TLSv1.1","TLSv1.2"};
	
	private static SSLContext createSSLContext(IPlainClientConfiguration sec)
	{
		X509Credential credential = sec.doSSLAuthn() ? sec.getCredential() : null;
		try
		{
			SSLContext sslContext = SSLContextCreator.createSSLContext(credential, sec.getValidator(), 
					"TLS", "HTTP Client", logger);
			sslContext.getSupportedSSLParameters().setProtocols(protocols);
			return sslContext;
		} catch (Exception e)
		{
			logger.fatal(e.getMessage(), e);
			throw new RuntimeException(e);
		}
	}
}

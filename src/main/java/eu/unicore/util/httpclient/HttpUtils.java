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

import org.apache.hc.client5.http.auth.AuthCache;
import org.apache.hc.client5.http.auth.AuthScheme;
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
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpRequestInterceptor;
import org.apache.hc.core5.http.config.Registry;
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

	public static PoolingHttpClientConnectionManager getSSLConnectionManager(IClientConfiguration security)
	{
		SSLContext sslContext = createSSLContext(security);
		HostnameVerifier hostnameVerifier = new EmptyHostnameVerifier();
		SSLConnectionSocketFactory sslsf = new CustomSSLConnectionSocketFactory(sslContext, hostnameVerifier);
		ConnectionSocketFactory plainsf = nioSocketFactory();
		Registry<ConnectionSocketFactory> r = RegistryBuilder.<ConnectionSocketFactory>create()
		        .register("http", plainsf)
		        .register("https", sslsf)
		        .build();
		return new PoolingHttpClientConnectionManager(r);
	}
	
	private static ConnectionSocketFactory nioSocketFactory() {
		return new PlainConnectionSocketFactory() {
			@Override
			public Socket createSocket(HttpContext context) throws IOException {
				return SocketChannel.open().socket();
			}
		};
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
			AuthCache authCache = (AuthCache) context.getAttribute(HttpClientContext.AUTH_CACHE);
			if (authCache == null)
			{
				authCache = new BasicAuthCache();
				context.setAttribute(HttpClientContext.AUTH_CACHE, authCache);				
			}
			
			if (authCache.get(host) == null)
			{
				AuthScheme scheme = new BasicScheme();
				authCache.put(host, scheme);
			}
		}
	}
	

	static String[] protocols = {"TLSv1","TLSv1.1","TLSv1.2"};
	
	public static SSLContext createSSLContext(IPlainClientConfiguration sec)
	{
		X509Credential credential = sec.doSSLAuthn() ? sec.getCredential() : null;
		try
		{
			SSLContext sslContext = SSLContextCreator.createSSLContext(credential, sec.getValidator(), 
					"TLS", "HTTP Client", logger, sec.getServerHostnameCheckingMode());
			sslContext.getSupportedSSLParameters().setProtocols(protocols);
			return sslContext;
		} catch (Exception e)
		{
			throw new RuntimeException(e);
		}
	}
}

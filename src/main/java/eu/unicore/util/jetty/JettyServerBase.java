package eu.unicore.util.jetty;

import java.net.MalformedURLException;
import java.net.URL;

import org.apache.logging.log4j.Logger;
import org.eclipse.jetty.ee10.servlet.ErrorHandler;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.rewrite.handler.HeaderPatternRule;
import org.eclipse.jetty.rewrite.handler.RewriteHandler;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.NetworkConnectionLimit;
import org.eclipse.jetty.server.NetworkConnector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.handler.CrossOriginHandler;
import org.eclipse.jetty.session.DefaultSessionIdManager;
import org.eclipse.jetty.session.SessionIdManager;
import org.eclipse.jetty.util.Callback;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import eu.unicore.security.canl.IAuthnAndTrustConfiguration;
import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.jetty.HttpServerProperties.XFrameOptions;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Wraps a Jetty server and allows to configure it using {@link IAuthnAndTrustConfiguration}<br/>
 * This class is useful for subclassing when creating a custom Jetty server. Subclasses must call 
 * {@link #initServer()} method in constructor to initialize the server.
 * 
 * @author schuller
 * @author K. Benedyczak
 */
public abstract class JettyServerBase {

	private static final Logger logger=Log.getLogger(Log.HTTP_SERVER, JettyServerBase.class);

	protected final URL[] listenUrls;
	protected final IAuthnAndTrustConfiguration securityConfiguration;
	protected final HttpServerProperties extraSettings;

	private Handler rootHandler;
	private Server theServer;

	/**
	 * Simplified constructor with only a single listen URL
	 *
	 * @param listenUrl listen URL
	 * @param secConfiguration security configuration, providing local credential and trust settings.
	 *        Useful only for https:// URLs
	 * @param extraSettings additional Jetty settings
	 * @throws ConfigurationException
	 */
	public JettyServerBase(URL listenUrl,
			IAuthnAndTrustConfiguration secConfiguration,
			HttpServerProperties extraSettings) throws ConfigurationException
	{
		this(new URL[] {listenUrl}, secConfiguration, extraSettings);
	}

	/**
	 * @param listenUrls listen URLs
	 * @param secConfiguration security configuration, providing local credential and trust settings.
	 *        Useful only for https:// URLs
	 * @param extraSettings additional Jetty settings
	 * @throws ConfigurationException
	 */
	public JettyServerBase(URL[] listenUrls,
			IAuthnAndTrustConfiguration secConfiguration,
			HttpServerProperties extraSettings) throws ConfigurationException
	{
		this.securityConfiguration = secConfiguration;
		this.listenUrls = listenUrls;
		this.extraSettings = extraSettings;
	}

	public void start() throws Exception{
		logger.debug("Starting Jetty HTTP server");
		theServer.start();
		updatePortsIfNeeded();
		logger.info("Jetty HTTP server was started");
	}

	public void stop() throws Exception{
		logger.debug("Stopping Jetty HTTP server");
		theServer.stop();
		logger.info("Jetty HTTP server was stopped");
	}

	protected void initServer() throws ConfigurationException{
		if (listenUrls.length == 1 && "0.0.0.0".equals(listenUrls[0].getHost())) {
			logger.info("Creating Jetty HTTP server, will listen on all network interfaces");
		} else {
			StringBuilder allAddresses = new StringBuilder();
			for (URL url: listenUrls)
				allAddresses.append(url).append(" ");
			logger.info("Creating Jetty HTTP server, will listen on: {}", allAddresses);	
		}
		theServer = createServer();
		configureSessionIdManager(extraSettings.getBooleanValue(HttpServerProperties.FAST_RANDOM));
		Connector[] connectors = createConnectors();
		for (Connector connector: connectors) {
			theServer.addConnector(connector);
		}
		configureResourceMonitoring();
		rootHandler = createRootHandler();
		Handler handler = configureHandlers(rootHandler);
		theServer.setHandler(handler);
		handler.setServer(theServer);
		configureErrorHandler();
	}

	protected Server createServer(){
		return new Server(getThreadPool()) {
			@Override
		    public boolean handle(Request request, Response response, Callback callback) throws Exception {
		        if ("TRACE".equals(request.getMethod())){
		            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
		            callback.succeeded();
		            return true;
		        } else {
		            return super.handle(request, response, callback);
		        }
			}
		};
	}

	protected void configureErrorHandler()
	{
		ErrorHandler errorHandler = new ErrorHandler();
		errorHandler.setShowCauses(false);
		errorHandler.setShowStacks(false);
		errorHandler.setShowOrigin(false);
		theServer.setErrorHandler(errorHandler);
	}

	protected QueuedThreadPool getThreadPool()
	{
		QueuedThreadPool btPool=new QueuedThreadPool();
		int extraThreads = listenUrls.length * 3;
		btPool.setMaxThreads(extraSettings.getIntValue(HttpServerProperties.MAX_THREADS) + extraThreads);
		btPool.setMinThreads(extraSettings.getIntValue(HttpServerProperties.MIN_THREADS) + extraThreads);
		return btPool;
	}

	/**
	 * configure all the handlers that need to be chained around the root handler
	 * @param toWrap
	 * @return
	 */
	protected Handler configureHandlers(Handler toWrap) {
		Handler handler = configureCORS(rootHandler);
		handler = configureGzip(handler);
		handler = configureFrame(handler);
		handler = configureHsts(handler);
		return handler;
	}

	protected Handler configureFrame(Handler toWrap)
	{
		XFrameOptions frameOpts = extraSettings.getEnumValue(
				HttpServerProperties.FRAME_OPTIONS, XFrameOptions.class);
		if (frameOpts != XFrameOptions.allow)
		{
			RewriteHandler rewriter = new RewriteHandler();
			rewriter.setHandler(toWrap);	
			HeaderPatternRule frameOriginRule = new HeaderPatternRule();
			frameOriginRule.setHeaderName("X-Frame-Options");
			StringBuilder sb = new StringBuilder(frameOpts.toHttp());
			if (frameOpts == XFrameOptions.allowFrom)
			{
				String allowedOrigin = extraSettings.getValue(
						HttpServerProperties.ALLOWED_TO_EMBED);
				sb.append(" ").append(allowedOrigin);
			}
			frameOriginRule.setHeaderValue(sb.toString());
			frameOriginRule.setPattern("*");
			rewriter.addRule(frameOriginRule);
			return rewriter;
		}
		return toWrap;
	}
	
	protected Handler configureHsts(Handler toWrap)
	{
		if (extraSettings.getBooleanValue(HttpServerProperties.ENABLE_HSTS))
		{
			RewriteHandler rewriter = new RewriteHandler();
			rewriter.setHandler(toWrap);
			HeaderPatternRule hstsRule = new HeaderPatternRule();
			hstsRule.setHeaderName("Strict-Transport-Security");
			hstsRule.setHeaderValue("max-age=31536000; includeSubDomains");
			hstsRule.setPattern("*");
			rewriter.addRule(hstsRule);
			return rewriter;
		}
		else {
			return toWrap;
		}
	}

	protected void configureSessionIdManager(boolean useFastRandom) {
		if (useFastRandom){
			logger.debug("Using fast (but less secure) session ID generator");
			SessionIdManager sm = new DefaultSessionIdManager(theServer, 
					new java.util.Random());
			theServer.addBean(sm);
		}
	}
	
	protected Connector[] createConnectors() throws ConfigurationException {
		ServerConnector[] ret = new ServerConnector[listenUrls.length];
		for (int i=0; i<listenUrls.length; i++) {
			ret[i] = createConnector(listenUrls[i]);
			configureConnector(ret[i], listenUrls[i]);
		}
		return ret;
	}

	/**
	 * Default connector creation: uses {@link #createSecureConnector(URL)} and {@link #createPlainConnector(URL)}
	 * depending on the URL protocol. Returns a fully configured connector.
	 * @param url
	 * @throws ConfigurationException 
	 */
	protected ServerConnector createConnector(URL url) throws ConfigurationException {
		ServerConnector connector;
		if (url.getProtocol().startsWith("https")) {
			connector = createSecureConnector(url);
		} else {
			connector = createPlainConnector(url);
		}
		return connector;
	}
	
	/**
	 * @return an instance of NIO secure connector. It uses proper validators and credentials
	 * and lowResourcesConnections are set to the difference between MAX and LOW THREADS.
	 * @throws Exception 
	 */
	protected SecuredServerConnector getSecuredConnectorInstance() throws ConfigurationException {
		HttpConnectionFactory httpConnFactory = getHttpConnectionFactory();
		SslContextFactory.Server secureContextFactory;
		try
		{
			secureContextFactory = SecuredServerConnector.createContextFactory(
					securityConfiguration.getValidator(), 
					securityConfiguration.getCredential());
		} catch (Exception e)
		{
			throw new ConfigurationException("Can't create secure context factory", e);
		}
		SecuredServerConnector connector = new SecuredServerConnector(theServer, 
				secureContextFactory, httpConnFactory);
		return connector;
	}
	
	/**
	 * Try not to override this method. It is better to override 
	 * {@link #getSecuredConnectorInstance()} instead. 
	 * This method creates a secure connector and configures 
	 * it with security-related settings.
	 * @param url
	 * @throws ConfigurationException
	 */
	protected ServerConnector createSecureConnector(URL url) throws ConfigurationException {
		logger.debug("Creating SSL connector on: {}", url);
		SecuredServerConnector ssl = getSecuredConnectorInstance();			
		SslContextFactory.Server factory = ssl.getSslContextFactory();
		factory.setNeedClientAuth(extraSettings.getBooleanValue(HttpServerProperties.REQUIRE_CLIENT_AUTHN));
		factory.setWantClientAuth(extraSettings.getBooleanValue(HttpServerProperties.WANT_CLIENT_AUTHN));
		String disabledCiphers = extraSettings.getValue(HttpServerProperties.DISABLED_CIPHER_SUITES);
		if (disabledCiphers != null) {
			disabledCiphers = disabledCiphers.trim();
			if (disabledCiphers.length() > 1)
				factory.setExcludeCipherSuites(disabledCiphers.split("[ ]+"));
		}
		String disabledProtocols = extraSettings.getValue(HttpServerProperties.DISABLED_PROTOCOLS);
		if (disabledProtocols != null) {
			disabledProtocols = disabledProtocols.trim();
			if (disabledProtocols.length() > 1)
				factory.setExcludeProtocols(disabledProtocols.split("[ ]+"));
		}
		logger.debug("SSL protocol was set to: '{}'", factory.getProtocol());
		return ssl;
	}	

	/**
	 * @return an instance of insecure connector. It is only configured not to send server version
	 * and supports connections logging.  
	 * @throws Exception 
	 */
	protected ServerConnector getPlainConnectorInstance() {
		HttpConnectionFactory httpConnFactory = getHttpConnectionFactory();
		return new PlainServerConnector(theServer, httpConnFactory);
	}
	
	/**
	 * By default http connection factory is configured not to send server identification data.
	 */
	protected HttpConnectionFactory getHttpConnectionFactory()
	{
		HttpConfiguration httpConfig = new HttpConfiguration();
		httpConfig.setSendServerVersion(false);
		httpConfig.setSendXPoweredBy(false);
		boolean sni = extraSettings.getBooleanValue(HttpServerProperties.ENABLE_SNI);
		SecureRequestCustomizer src = new SecureRequestCustomizer();
		src.setSniHostCheck(sni);
		httpConfig.addCustomizer(src);
		return new HttpConnectionFactory(httpConfig);
	}
	
	
	/**
	 * Try not to override this method. It is better to override 
	 * {@link #getPlainConnectorInstance()} instead. 
	 * This method creates an insecure connector and configures it.
	 * 
	 * @param url
	 */
	protected ServerConnector createPlainConnector(URL url){
		logger.debug("Creating plain HTTP connector on: {}", url);
		return getPlainConnectorInstance();
	}

	/**
	 * sets parameters on the Connector, which are shared by all of them regardless of their type.
	 * The default implementation sets port and hostname.
	 * @throws ConfigurationException 
	 */
	protected void configureConnector(ServerConnector connector, URL url) throws ConfigurationException {
		connector.setHost(url.getHost());
		connector.setPort(url.getPort() == -1 ? url.getDefaultPort() : url.getPort());
		connector.setIdleTimeout(extraSettings.getIntValue(HttpServerProperties.MAX_IDLE_TIME));
	}

	protected void configureResourceMonitoring() throws ConfigurationException {
		Integer maxConnections = extraSettings.getIntValue(HttpServerProperties.MAX_CONNECTIONS);
		if (maxConnections > 0) {
			theServer.addBean(new NetworkConnectionLimit(maxConnections, theServer));
		}
	}

	/**
	 * Configures Gzip filter if gzipping is enabled, for all servlet handlers which are configured.
	 * Warning: if you use a complex setup of handlers it might be better to override this method and
	 * enable compression selectively.
	 * @throws ConfigurationException
	 */
	protected Handler configureGzip(Handler handler) throws ConfigurationException {
		boolean enableGzip = extraSettings.getBooleanValue(HttpServerProperties.ENABLE_GZIP);
		if (enableGzip) {
			try {
				// use full classnames here, so this class will work even if the 
				// (optional!) compression jars are not on the classpath
				var compressionHandler = new org.eclipse.jetty.compression.server.CompressionHandler(handler);
				compressionHandler.setServer(theServer);
				compressionHandler.setHandler(handler);
				var gzip = new org.eclipse.jetty.compression.gzip.GzipCompression(); 
				gzip.setMinCompressSize(extraSettings.getIntValue(HttpServerProperties.MIN_GZIP_SIZE));
				compressionHandler.putCompression(gzip);
				logger.info("Enabling GZIP compression filter");
				return compressionHandler;
			}catch(Exception e) {
				logger.error("Could not setup GZIP - check classpath for the required jetty-compression-* jars.", e);
			}
		}
		return handler;
	}

	/**
	 * configures Cross Origin Resource Sharing
	 * @throws ConfigurationException
	 */
	protected Handler configureCORS(Handler handler) throws ConfigurationException {
		boolean enable = extraSettings.getBooleanValue(HttpServerProperties.ENABLE_CORS);
		if (enable && handler instanceof ServletContextHandler) {
			logger.info("Enabling CORS");
			CrossOriginHandler cors = new CrossOriginHandler();
			cors.setServer(theServer);
			cors.setHandler(handler);
			return cors;
		}
		else {
			return handler;
		}
		
	}
	
	/**
	 * Invoked after server is started: updates the listen URLs with the actual port,
	 * if originally it was set to 0, what means that server should choose a random one
	 */
	protected void updatePortsIfNeeded() {
		Connector[] conns = theServer.getConnectors();

		for (int i=0; i<listenUrls.length; i++) {
			URL url = listenUrls[i];
			if (url.getPort() == 0) {
				int port = ((NetworkConnector)conns[i]).getLocalPort();
				try {
					listenUrls[i] = new URL(url.getProtocol(), 
							url.getHost(), port, url.getFile());
				} catch (MalformedURLException e) {
					throw new RuntimeException("Ups, URL can not " +
							"be reconstructed, while it should", e);
				}
			}
		}
	}
		
	/**
	 * Implement this method to create server's handlers - usually returning Servlet's handler.
	 * @throws Exception
	 */
	protected abstract Handler createRootHandler() throws ConfigurationException;
	
	/**
	 * @return the root handler of this Jetty server as returned by {@link #createRootHandler()} 
	 */
	public Handler getRootHandler() 
	{
		return rootHandler;
	}

	/**
	 * @return the root handler of this Jetty server - it is a wrapper of the 
	 * handler returned by the {@link #getRootHandler()}
	 */
	public Handler getRootHandlerLowLevel() 
	{
		return theServer.getHandler();
	}
	
	/**
	 * @return server the Jetty server
	 */
	public Server getServer(){
		return theServer;
	}
	
	/**
	 * @return array of URLs where the server is listening
	 */
	public URL[] getUrls() {
		return listenUrls;
	}
	
	public void reloadCredential() {
		for(Connector connector: theServer.getConnectors()) {
			try{
				if(connector instanceof SecuredServerConnector) {
					logger.info("Reloading credential on {}", connector.getServer().getURI());
					@SuppressWarnings("resource")
					SecuredServerConnector sConnector = (SecuredServerConnector)connector;
					SslContextFactory.Server scf = sConnector.getSslContextFactory();
					JettyConnectorUtils.reloadCredential(scf,
							securityConfiguration.getCredential(),
							securityConfiguration.getValidator(),
							logger);
				}
			}catch(Exception ex) {
				logger.error("Cannot reload credential.",ex);
			}
		}
	}

}

/*********************************************************************************
 * Copyright (c) 2006 Forschungszentrum Juelich GmbH 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * (1) Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the disclaimer at the end. Redistributions in
 * binary form must reproduce the above copyright notice, this list of
 * conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * 
 * (2) Neither the name of Forschungszentrum Juelich GmbH nor the names of its 
 * contributors may be used to endorse or promote products derived from this 
 * software without specific prior written permission.
 * 
 * DISCLAIMER
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ********************************************************************************/


package eu.unicore.util.jetty;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Enumeration;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.eclipse.jetty.rewrite.handler.HeaderPatternRule;
import org.eclipse.jetty.rewrite.handler.RewriteHandler;
import org.eclipse.jetty.rewrite.handler.Rule;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.LowResourceMonitor;
import org.eclipse.jetty.server.NetworkConnector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SessionIdManager;
import org.eclipse.jetty.server.handler.AbstractHandlerContainer;
import org.eclipse.jetty.server.handler.gzip.GzipHandler;
import org.eclipse.jetty.server.session.DefaultSessionIdManager;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlets.CrossOriginFilter;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import eu.unicore.security.canl.IAuthnAndTrustConfiguration;
import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.jetty.HttpServerProperties.XFrameOptions;

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

	protected final Class<? extends JettyLogger> jettyLogger;
	protected final URL[] listenUrls;
	protected final IAuthnAndTrustConfiguration securityConfiguration;
	protected final HttpServerProperties extraSettings;

	private Handler rootHandler;
	private Server theServer;

	/**
	 * Simplified constructor: only one listen URL, standard {@link JettyLogger} is used which is logging to log4j 
	 * without SLF.
	 * @param listenUrl listen URL
	 * @param secConfiguration security configuration, providing local credential and trust settings.
	 * Useful only for https:// URLs
	 * @param extraSettings additional Jetty settings
	 * @throws ConfigurationException
	 */
	public JettyServerBase(URL listenUrl,
			IAuthnAndTrustConfiguration secConfiguration,
			HttpServerProperties extraSettings) throws ConfigurationException
	{
		this(new URL[] {listenUrl}, secConfiguration, extraSettings, JettyLogger.class);
	}
	
	/**
	 * 
	 * @param listenUrls listen URLs
	 * @param secConfiguration security configuration, providing local credential and trust settings.
	 * Useful only for https:// URLs
	 * @param extraSettings additional Jetty settings
	 * @param jettyLogger either a custom extension of {@link JettyLogger} or null. In latter case a default
	 * Jetty logging will be used, which is either SLF or trivial logging to standard error if SLF 
	 * is not present. 
	 * @throws ConfigurationException
	 */
	public JettyServerBase(URL[] listenUrls,
			IAuthnAndTrustConfiguration secConfiguration,
			HttpServerProperties extraSettings,
			Class<? extends JettyLogger> jettyLogger) throws ConfigurationException
	{
		this.securityConfiguration = secConfiguration;
		this.jettyLogger = jettyLogger;
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
		if (jettyLogger != null) {
			logger.debug("Setting a custom class for handling Jetty logging: " + jettyLogger.getName());
			System.setProperty("org.eclipse.jetty.util.log.class", jettyLogger.getName());
		}
		if (listenUrls.length == 1 && "0.0.0.0".equals(listenUrls[0].getHost())) {
			logger.info("Creating Jetty HTTP server, will listen on all network interfaces");
		} else {
			StringBuilder allAddresses = new StringBuilder();
			for (URL url: listenUrls)
				allAddresses.append(url).append(" ");
			logger.info("Creating Jetty HTTP server, will listen on: " + allAddresses);	
		}
		
		theServer = createServer();
		
		configureSessionIdManager(extraSettings.getBooleanValue(HttpServerProperties.FAST_RANDOM));

		Connector[] connectors = createConnectors();
		for (Connector connector: connectors) {
			theServer.addConnector(connector);
		}
		
		configureResourceMonitoring();
		rootHandler = createRootHandler();
		try{
			rootHandler = configureCORS(rootHandler);
		}catch(ServletException se){
			throw new ConfigurationException("Error setting up CORS", se);
		}
		AbstractHandlerContainer headersRewriteHandler = configureHttpHeaders(rootHandler);
		configureGzipHandler(headersRewriteHandler);
		configureErrorHandler();
	}

	protected Server createServer(){
		Server server = new Server(getThreadPool()){
			@Override
		    public void handle(HttpChannel connection) throws IOException, ServletException {
		        Request request=connection.getRequest();
		        Response response=connection.getResponse();

		        if ("TRACE".equals(request.getMethod())){
		            request.setHandled(true);
		            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
		        } else {
		            super.handle(connection);
		        }
		    }
		};
		return server;
	}
	
	protected void configureGzipHandler(AbstractHandlerContainer headersRewriteHandler)
	{
		Handler withGzip = configureGzip(headersRewriteHandler);
		theServer.setHandler(withGzip);
	}
	
	protected void configureErrorHandler()
	{
		theServer.addBean(new JettyErrorHandler(theServer));
	}
	
	protected QueuedThreadPool getThreadPool()
	{
		QueuedThreadPool btPool=new QueuedThreadPool();
		int extraThreads = listenUrls.length * 3;
		btPool.setMaxThreads(extraSettings.getIntValue(HttpServerProperties.MAX_THREADS) + extraThreads);
		btPool.setMinThreads(extraSettings.getIntValue(HttpServerProperties.MIN_THREADS) + extraThreads);
		return btPool;
	}

	protected AbstractHandlerContainer configureHttpHeaders(Handler toWrap)
	{
		RewriteHandler rewriter = new RewriteHandler();
		rewriter.setRewriteRequestURI(false);
		rewriter.setRewritePathInfo(false);
		rewriter.setHandler(toWrap);

		//workaround for Jetty bug: RewriteHandler without any rule won't work
		rewriter.setRules(new Rule[0]);
		
		if (extraSettings.getBooleanValue(HttpServerProperties.ENABLE_HSTS))
		{
			HeaderPatternRule hstsRule = new HeaderPatternRule();
			hstsRule.setName("Strict-Transport-Security");
			hstsRule.setValue("max-age=31536000; includeSubDomains");
			hstsRule.setPattern("*");
			rewriter.addRule(hstsRule);
		}
		
		XFrameOptions frameOpts = extraSettings.getEnumValue(
				HttpServerProperties.FRAME_OPTIONS, XFrameOptions.class);
		if (frameOpts != XFrameOptions.allow)
		{
			HeaderPatternRule frameOriginRule = new HeaderPatternRule();
			frameOriginRule.setName("X-Frame-Options");
			
			StringBuilder sb = new StringBuilder(frameOpts.toHttp());
			if (frameOpts == XFrameOptions.allowFrom)
			{
				String allowedOrigin = extraSettings.getValue(
						HttpServerProperties.ALLOWED_TO_EMBED);
				sb.append(" ").append(allowedOrigin);
			}
			frameOriginRule.setValue(sb.toString());
			frameOriginRule.setPattern("*");
			rewriter.addRule(frameOriginRule);
		}
		return rewriter;
	}
	
	protected void configureSessionIdManager(boolean useFastRandom) {
		if (useFastRandom){
			logger.info("Using fast (but less secure) session ID generator");
			SessionIdManager sm = new DefaultSessionIdManager(theServer, 
					new java.util.Random());
			theServer.setSessionIdManager(sm);
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
		SslContextFactory secureContextFactory;
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
		logger.debug("Creating SSL NIO connector on: " + url);
		SecuredServerConnector ssl = getSecuredConnectorInstance();			

		SslContextFactory factory = ssl.getSslContextFactory();
		factory.setNeedClientAuth(extraSettings.getBooleanValue(HttpServerProperties.REQUIRE_CLIENT_AUTHN));
		factory.setWantClientAuth(extraSettings.getBooleanValue(HttpServerProperties.WANT_CLIENT_AUTHN));
		String disabledCiphers = extraSettings.getValue(HttpServerProperties.DISABLED_CIPHER_SUITES);
		if (disabledCiphers != null) {
			disabledCiphers = disabledCiphers.trim();
			if (disabledCiphers.length() > 1)
				factory.setExcludeCipherSuites(disabledCiphers.split("[ ]+"));
		}
		logger.debug("SSL protocol was set to: '"+factory.getProtocol()+"'");
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
		logger.debug("Creating plain HTTP connector on: " + url);
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
		connector.setSoLingerTime(extraSettings.getIntValue(HttpServerProperties.SO_LINGER_TIME));
		connector.setIdleTimeout(extraSettings.getIntValue(HttpServerProperties.MAX_IDLE_TIME));
	}

	protected void configureResourceMonitoring() throws ConfigurationException {
		Integer highLoadConnections = extraSettings.getIntValue(HttpServerProperties.HIGH_LOAD_CONNECTIONS);
		if (highLoadConnections >= 0)
			theServer.addBean(getResourcesMonitor());
	}

	/**
	 * Configures Gzip filter if gzipping is enabled, for all servlet handlers which are configured.
	 * Warning: if you use a complex setup of handlers it might be better to override this method and
	 * enable compression selectively.
	 * @throws ConfigurationException
	 */
	protected AbstractHandlerContainer configureGzip(AbstractHandlerContainer handler) throws ConfigurationException {
		boolean enableGzip = extraSettings.getBooleanValue(HttpServerProperties.ENABLE_GZIP);
		if (enableGzip) {
			GzipHandler gzipHandler = new GzipHandler();
			gzipHandler.setMinGzipSize(extraSettings.getIntValue(HttpServerProperties.MIN_GZIP_SIZE));
			logger.info("Enabling GZIP compression filter");
			gzipHandler.setServer(theServer);
			gzipHandler.setHandler(handler);
			return gzipHandler;
		} else
			return handler;
	}
	
	/**
	 * configures Cross Origin Resource Sharing
	 * @throws ConfigurationException
	 */
	protected Handler configureCORS(Handler handler) throws ConfigurationException, ServletException {
		boolean enable = extraSettings.getBooleanValue(HttpServerProperties.ENABLE_CORS);
		if (enable && handler instanceof ServletContextHandler) {
			logger.info("Enabling CORS");
			CrossOriginFilter cors = new CrossOriginFilter();
			FilterConfig config = new FilterConfig() {
				
				@Override
				public ServletContext getServletContext() {
					// TODO Auto-generated method stub
					return null;
				}
				
				@Override
				public Enumeration<String> getInitParameterNames() {
					// TODO Auto-generated method stub
					return null;
				}
				
				@Override
				public String getInitParameter(String name) {
					return extraSettings.getValue("CORS_"+name); 
				}
				
				@Override
				public String getFilterName() {
					// TODO Auto-generated method stub
					return null;
				}
			};
			cors.init(config);
			FilterHolder h = new FilterHolder();
			h.setFilter(cors);
			((ServletContextHandler)handler).addFilter(h, "*", null);
		}
		return handler;
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
	public AbstractHandlerContainer getRootHandlerLowLevel() 
	{
		return (AbstractHandlerContainer) theServer.getHandler();
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
	
	protected LowResourceMonitor getResourcesMonitor()
	{
		LowResourceMonitor ret = new LowResourceMonitor(theServer);
		
		ret.setMaxConnections(extraSettings.getIntValue(HttpServerProperties.HIGH_LOAD_CONNECTIONS));
		ret.setLowResourcesIdleTimeout(extraSettings.getIntValue(
			HttpServerProperties.LOW_RESOURCE_MAX_IDLE_TIME));
		
		
		return ret;
	}
}

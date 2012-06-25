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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.EnumSet;
import java.util.Properties;

import javax.servlet.DispatcherType;

import org.apache.log4j.Logger;
import org.eclipse.jetty.server.AbstractConnector;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HandlerContainer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.SessionIdManager;
import org.eclipse.jetty.server.bio.SocketConnector;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
import org.eclipse.jetty.server.session.HashSessionIdManager;
import org.eclipse.jetty.server.ssl.SslConnector;
import org.eclipse.jetty.server.ssl.SslSelectChannelConnector;
import org.eclipse.jetty.server.ssl.SslSocketConnector;
import org.eclipse.jetty.servlet.FilterHolder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.QueuedThreadPool;

import eu.unicore.security.canl.AuthnAndTrustProperties;
import eu.unicore.security.canl.IAuthnAndTrustConfiguration;
import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;

/**
 * Wraps a Jetty server and allows to configure it using {@link AuthnAndTrustProperties}<br/>
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
	protected final JettyProperties extraSettings;
	
	private Server theServer;
	private Handler rootContext;

	public JettyServerBase(URL listenUrl,
			IAuthnAndTrustConfiguration secConfiguration,
			JettyProperties extraSettings) throws ConfigurationException
	{
		this(new URL[] {listenUrl}, secConfiguration, extraSettings, JettyLogger.class);
	}
	
	public JettyServerBase(URL[] listenUrls,
			IAuthnAndTrustConfiguration secConfiguration,
			JettyProperties extraSettings,
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
		System.setProperty("org.eclipse.jetty.util.log.class", jettyLogger.getName()); 
		if (listenUrls.length == 1 && "0.0.0.0".equals(listenUrls[0].getHost())) {
			logger.info("Creating Jetty HTTP server, will listen on all network interfaces");
		} else {
			StringBuilder allAddresses = new StringBuilder();
			for (URL url: listenUrls)
				allAddresses.append(url).append(" ");
			logger.info("Creating Jetty HTTP server, will listen on: " + allAddresses);	
		}
		theServer = new Server();
		

		configureSessionIdManager(extraSettings.getBooleanValue(JettyProperties.FAST_RANDOM));

		Connector[] connectors = createConnectors();
		for (Connector connector: connectors) {
			theServer.addConnector(connector);
		}
		
		configureServer();
		this.rootContext = createRootContext();
		theServer.setHandler(rootContext);
		configureGzip();
	}

	protected void configureSessionIdManager(boolean useFastRandom) {
		if (useFastRandom){
			logger.info("Using fast (but less secure) session ID generator");
			SessionIdManager sm = new HashSessionIdManager(new java.util.Random());
			theServer.setSessionIdManager(sm);
		}
	}
	
	protected Connector[] createConnectors() throws ConfigurationException {
		AbstractConnector[] ret = new AbstractConnector[listenUrls.length];
		for (int i=0; i<listenUrls.length; i++) {
			ret[i] = createConnector(listenUrls[i]);
			configureConnector(ret[i], listenUrls[i]);
		}
		return ret;
	}

	/**
	 * Default connector creation: uses {@link #createSecureConnector()} and {@link #createPlainConnector()}
	 * depending on the URL protocol. Returns a fully configured connector.
	 * @param url
	 * @return
	 * @throws ConfigurationException 
	 */
	protected AbstractConnector createConnector(URL url) throws ConfigurationException {
		AbstractConnector connector;
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
	 */
	protected SslSelectChannelConnector getNioSecuredConnectorInstance() {
		NIOSSLSocketConnector ssl;
		try
		{
			ssl = new NIOSSLSocketConnector(securityConfiguration.getValidator(), 
					securityConfiguration.getCredential());
		} catch (Exception e)
		{
			throw new RuntimeException("Can not create Jetty NIO SSL connector, shouldn't happen.", e);
		}
		ssl.setLowResourcesConnections(extraSettings.getIntValue(JettyProperties.HIGH_LOAD_CONNECTIONS));
		return ssl;
	}
	
	/**
	 * @return an instance of OIO (classic) secure connector. It uses proper validators and credentials
	 * but is not configured in any other way.  
	 */
	protected SslSocketConnector getClassicSecuredConnectorInstance() {
		try
		{
			return new CustomSslSocketConnector(
					securityConfiguration.getValidator(), securityConfiguration.getCredential());
		} catch (Exception e)
		{
			throw new RuntimeException("Can not create Jetty SSL connector, shouldn't happen.", e);
		}
	}
	
	/**
	 * Try not to override this method. It is better to override {@link #getClassicSecuredConnectorInstance()}
	 * and/or {@link #getNioSecuredConnectorInstance()} instead. 
	 * This method creates a NIO or OIO (classic) secure connector and configures 
	 * it with security-related settings.
	 * @param url
	 * @return
	 * @throws ConfigurationException
	 */
	protected AbstractConnector createSecureConnector(URL url) throws ConfigurationException {
		boolean useNio = extraSettings.getBooleanValue(JettyProperties.USE_NIO);
		SslConnector ssl;
		if (useNio) {
			logger.debug("Creating SSL NIO connector on: " + url);
			ssl = getNioSecuredConnectorInstance();			
		} else {
			logger.debug("Creating SSL connector on: " + url);
			ssl = getClassicSecuredConnectorInstance();
		}

		SslContextFactory factory = ssl.getSslContextFactory();
		factory.setNeedClientAuth(extraSettings.getBooleanValue(JettyProperties.REQUIRE_CLIENT_AUTHN));
		factory.setWantClientAuth(extraSettings.getBooleanValue(JettyProperties.WANT_CLIENT_AUTHN));
		String disabledCiphers = extraSettings.getValue(JettyProperties.DISABLED_CIPHER_SUITES);
		if (disabledCiphers != null) {
			disabledCiphers = disabledCiphers.trim();
			if (disabledCiphers.length() > 1)
				factory.setExcludeCipherSuites(disabledCiphers.split("[ ]+"));
		}
		logger.debug("SSL protocol was set to: '"+factory.getProtocol()+"'");
		return (AbstractConnector) ssl;
	}	

	/**
	 * @return an instance of NIO insecure connector. It is not configured in any way.  
	 */
	protected SelectChannelConnector getNioPlainConnectorInstance() {
		return new SelectChannelConnector();
	}
	
	/**
	 * @return an instance of OIO (classic) insecure connector. It is not configured in any way.  
	 */
	protected SocketConnector getClassicPlainConnectorInstance() {
		return new SocketConnector();
	}

	/**
	 * Try not to override this method. It is better to override {@link #getClassicPlainConnectorInstance()}
	 * and/or {@link #getNioPlainConnectorInstance()} instead. 
	 * This method creates a NIO or OIO (classic) insecure connector and configures it.
	 * 
	 * @param url
	 * @return
	 */
	protected AbstractConnector createPlainConnector(URL url){
		boolean useNio = extraSettings.getBooleanValue(JettyProperties.USE_NIO);
		if (useNio) {
			logger.debug("Creating plain NIO HTTP connector on: " + url);
			SelectChannelConnector ret = getNioPlainConnectorInstance();
			ret.setLowResourcesConnections(extraSettings.getIntValue(JettyProperties.HIGH_LOAD_CONNECTIONS));
			return ret;
		} else {
			logger.debug("Creating plain HTTP connector on: " + url);
			return getClassicPlainConnectorInstance();
		}
	}

	/**
	 * sets parameters on the Connector, which are shared by all of them regardless of their type.
	 * The default implementation sets port and hostname.
	 * @throws ConfigurationException 
	 */
	protected void configureConnector(AbstractConnector connector, URL url) throws ConfigurationException {
		connector.setHost(url.getHost());
		connector.setPort(url.getPort() == -1 ? url.getDefaultPort() : url.getPort());
		connector.setSoLingerTime(extraSettings.getIntValue(JettyProperties.SO_LINGER_TIME));
		connector.setLowResourcesMaxIdleTime(extraSettings.getIntValue(
			JettyProperties.LOW_RESOURCE_MAX_IDLE_TIME));
		connector.setMaxIdleTime(extraSettings.getIntValue(JettyProperties.MAX_IDLE_TIME));
	}

	protected void configureServer() throws ConfigurationException {
		QueuedThreadPool btPool=new QueuedThreadPool();
		btPool.setMaxThreads(extraSettings.getIntValue(JettyProperties.MAX_THREADS));
		btPool.setMinThreads(extraSettings.getIntValue(JettyProperties.MIN_THREADS));
		theServer.setThreadPool(btPool);
	}

	/**
	 * Configures Gzip filter if gzipping is enabled, for all servlet handlers which are configured.
	 * Warning: if you use a complex setup of handlers it might be better to override this method and
	 * set the filter for the propert handlers.
	 * @throws ConfigurationException
	 */
	protected void configureGzip() throws ConfigurationException {
		boolean enableGzip = extraSettings.getBooleanValue(JettyProperties.ENABLE_GZIP);
		if (enableGzip) {
			FilterHolder gzipHolder = new FilterHolder(
					new ConfigurableGzipFilter(extraSettings));
			logger.info("Enabling GZIP compression filter");
			tryToAddGzipFilter(gzipHolder, getRootContext());
		}
	}
	
	protected void tryToAddGzipFilter(FilterHolder gzipHolder, Handler h) {
		if (h instanceof ServletContextHandler)
		{
			((ServletContextHandler)h).addFilter(gzipHolder, "/", 
					EnumSet.of(DispatcherType.REQUEST));
		} else if (h instanceof HandlerContainer)
		{
			Handler[] handlers = ((HandlerContainer)h).getChildHandlers();
			for (Handler handler: handlers)
				tryToAddGzipFilter(gzipHolder, handler);
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
				int port = conns[i].getLocalPort();
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
	protected abstract Handler createRootContext() throws ConfigurationException;
	
	/**
	 * 
	 * @return the root handler of this Jetty server. 
	 */
	public Handler getRootContext() 
	{
		return rootContext;
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
	
	/**
	 * @return Jetty settings useful for tests, with insecure random
	 */
	public static JettyProperties getSimpleTestSettings()
	{
		Properties p = new Properties();
		JettyProperties ret = new JettyProperties(p);
		ret.setProperty(JettyProperties.FAST_RANDOM, "true");
		ret.setProperty(JettyProperties.SO_LINGER_TIME, "1");
		return ret;
	}
}
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


package eu.unicore.security.util.jetty;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.mortbay.jetty.AbstractConnector;
import org.mortbay.jetty.Connector;
import org.mortbay.jetty.Handler;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.SessionIdManager;
import org.mortbay.jetty.bio.SocketConnector;
import org.mortbay.jetty.nio.SelectChannelConnector;
import org.mortbay.jetty.security.SslSelectChannelConnector;
import org.mortbay.jetty.security.SslSocketConnector;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.FilterHolder;
import org.mortbay.jetty.servlet.HashSessionIdManager;
import org.mortbay.thread.QueuedThreadPool;

import eu.unicore.security.util.AuthnAndTrustProperties;
import eu.unicore.security.util.ConfigurationException;
import eu.unicore.security.util.IAuthnAndTrustConfiguration;
import eu.unicore.security.util.Log;

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
	private Context rootContext;

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
		System.setProperty("org.mortbay.log.class", jettyLogger.getName()); 
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
		NIOSSLSocketConnector ssl = new NIOSSLSocketConnector(
				securityConfiguration.getValidator(), securityConfiguration.getCredential());
		long lowResourcesConnections = extraSettings.getIntValue(JettyProperties.MAX_THREADS)-
					extraSettings.getIntValue(JettyProperties.LOW_THREADS);
		ssl.setLowResourcesConnections(lowResourcesConnections);
		return ssl;
	}
	
	/**
	 * @return an instance of OIO (classic) secure connector. It uses proper validators and credentials
	 * but is not configured in any other way.  
	 */
	protected SslSocketConnector getClassicSecuredConnectorInstance() {
		return new CustomSslSocketConnector(
				securityConfiguration.getValidator(), securityConfiguration.getCredential());
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

		//WARNING!! this method contains a duplicated code, as secure NIO and OIO JettyConnectors
		//do not share a common interface for security related settings. Nevertheless the methods
		//are the same in both. Always fix both versions!
		if (useNio) {
			logger.debug("Creating SSL NIO connector on: " + url);
			SslSelectChannelConnector ssl = getNioSecuredConnectorInstance();			
			
			//duplicated code start
			ssl.setNeedClientAuth(extraSettings.getBooleanValue(JettyProperties.REQUIRE_CLIENT_AUTHN));
			ssl.setWantClientAuth(extraSettings.getBooleanValue(JettyProperties.WANT_CLIENT_AUTHN));
			String disabledCiphers = extraSettings.getValue(JettyProperties.DISABLED_CIPHER_SUITES);
			if (disabledCiphers != null) {
				disabledCiphers = disabledCiphers.trim();
				if (disabledCiphers.length() > 1)
					ssl.setExcludeCipherSuites(disabledCiphers.split("[ ]+"));
			}
			
			//fix for IBM JDK where default protocol "TLS" does not work
			String vm=System.getProperty("java.vm.vendor");
			if(vm!=null && vm.trim().startsWith("IBM")){
				ssl.setProtocol("SSL_TLS");//works for clients using both SSLv3 and TLS
				logger.info("For IBM JDK: Setting SSL protocol to '"+ssl.getProtocol()+"'");
			}
			//end
			return ssl;
		} else {
			logger.debug("Creating SSL connector on: " + url);
			SslSocketConnector ssl = getClassicSecuredConnectorInstance();

			//duplicated code start
			ssl.setNeedClientAuth(extraSettings.getBooleanValue(JettyProperties.REQUIRE_CLIENT_AUTHN));
			ssl.setWantClientAuth(extraSettings.getBooleanValue(JettyProperties.WANT_CLIENT_AUTHN));
			String disabledCiphers = extraSettings.getValue(JettyProperties.DISABLED_CIPHER_SUITES);
			if (disabledCiphers != null) {
				disabledCiphers = disabledCiphers.trim();
				if (disabledCiphers.length() > 1)
					ssl.setExcludeCipherSuites(disabledCiphers.split("[ ]+"));
			}
			
			//fix for IBM JDK where default protocol "TLS" does not work
			String vm=System.getProperty("java.vm.vendor");
			if(vm!=null && vm.trim().startsWith("IBM")){
				ssl.setProtocol("SSL_TLS");//works for clients using both SSLv3 and TLS
				logger.info("For IBM JDK: Setting SSL protocol to '"+ssl.getProtocol()+"'");
			}
			//end
			return ssl;
		}
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
	 * This method creates a NIO or OIO (classic) insecure connector. Currently it doesn't perform any
	 * additional configuration but in future may configure settings which are specific 
	 * to all insecure connectors.
	 * 
	 * @param url
	 * @return
	 */
	protected AbstractConnector createPlainConnector(URL url){
		boolean useNio = extraSettings.getBooleanValue(JettyProperties.USE_NIO);
		if (useNio) {
			logger.debug("Creating plain NIO HTTP connector on: " + url);
			return getNioPlainConnectorInstance();
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
		connector.setLowResourceMaxIdleTime(extraSettings.getIntValue(
			JettyProperties.LOW_RESOURCE_MAX_IDLE_TIME));
	}

	
	protected void configureServer() throws ConfigurationException {
		QueuedThreadPool btPool=new QueuedThreadPool();
		btPool.setMaxThreads(extraSettings.getIntValue(JettyProperties.MAX_THREADS));
		btPool.setMinThreads(extraSettings.getIntValue(JettyProperties.MIN_THREADS));
		btPool.setMaxIdleTimeMs(extraSettings.getIntValue(JettyProperties.MAX_IDLE_TIME));
		btPool.setLowThreads(extraSettings.getIntValue(JettyProperties.LOW_THREADS));
		if(btPool.getLowThreads()>btPool.getMaxThreads()){
			logger.warn("Resetting lowThreads parameter to '0' (must be smaller than maxThreads)");
			btPool.setLowThreads(0);
		}
		theServer.setThreadPool(btPool);
	}

	protected void configureGzip() throws ConfigurationException {
		boolean enableGzip = extraSettings.getBooleanValue(JettyProperties.ENABLE_GZIP);
		if (enableGzip) {
			FilterHolder gzipHolder = new FilterHolder(
					new ConfigurableGzipFilter(extraSettings));
			getRootContext().addFilter(gzipHolder, "/", Handler.REQUEST);
			logger.info("Enabling GZIP compression filter");
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
	 * Implement this method to add servlets to the server.
	 * @throws Exception
	 */
	protected abstract Context createRootContext() throws ConfigurationException;
	
	/**
	 * 
	 * @return the root context of this Jetty server. 
	 */
	public Context getRootContext() 
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

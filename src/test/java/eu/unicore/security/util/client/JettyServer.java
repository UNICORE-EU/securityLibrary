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

package eu.unicore.security.util.client;

import java.io.IOException;
import java.security.KeyStoreException;
import java.util.HashMap;

import org.mortbay.jetty.AbstractConnector;
import org.mortbay.jetty.Handler;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.SessionIdManager;
import org.mortbay.jetty.bio.SocketConnector;
import org.mortbay.jetty.handler.ContextHandlerCollection;
import org.mortbay.jetty.handler.DefaultHandler;
import org.mortbay.jetty.handler.HandlerCollection;
import org.mortbay.jetty.security.SslSocketConnector;
import org.mortbay.jetty.servlet.Context;
import org.mortbay.jetty.servlet.HashSessionIdManager;
import org.mortbay.thread.QueuedThreadPool;

import eu.emi.security.authn.x509.X509CertChainValidator;
import eu.emi.security.authn.x509.X509Credential;
import eu.emi.security.authn.x509.impl.KeystoreCertChainValidator;
import eu.emi.security.authn.x509.impl.KeystoreCredential;
import eu.unicore.security.util.jetty.CustomSslSocketConnector;


/**
 * a Jetty server hosting an xfire servlet
 * 
 * @author schuller
 */
public class JettyServer {
	public static final String KEYSTORE = "src/test/resources/client/httpserver.jks";
	public static final String KEYSTORE_P = "the!server";
	private int soLinger;
	
	private Server theServer;
	private String url, secUrl;
	private Context root;

	private ContextHandlerCollection contexts; // the list of ContextHandlers
	private HandlerCollection handlers; // the list of lists of Handlers
	private DefaultHandler defaultHandler; // default handler

	protected static final HashMap<String, Integer> defaults = new HashMap<String, Integer>();

	public JettyServer(int soLinger) throws Exception {
		this.soLinger = soLinger;
		initServer();
		root = new Context(theServer, "/", Context.SESSIONS);
		configureServer();
	}

	private void initServer() throws KeyStoreException, IOException {
		int port = 62407;
		String host = "127.0.0.1";
		url = "http://" + host + ":" + port;
		secUrl = "https://" + host + ":" + (port+1);
		theServer = new Server();
		theServer.addConnector(createSecureConnector(port+1, host));
		theServer.addConnector(createConnector(port, host));
	}

	public void start() throws Exception {
		theServer.start();
	}

	public void stop() throws Exception {
		theServer.stop();
	}

	protected void configureServer() {
		QueuedThreadPool btPool = new QueuedThreadPool();
		theServer.setThreadPool(btPool);
		SessionIdManager sm = new HashSessionIdManager(new java.util.Random());
		theServer.setSessionIdManager(sm);
	}

	protected AbstractConnector createConnector(int port, String host) {
		AbstractConnector connector = new SocketConnector();
		connector.setPort(port);
		connector.setHost(host);
		connector.setSoLingerTime(soLinger);
		return connector;
	}

	/**
	 * Set up the handler structure to receive a webapp. Also put in a
	 * DefaultHandler so we get a nice page than a 404 if we hit the root and
	 * the webapp's context isn't at root.
	 * 
	 * @throws Exception
	 */
	public void configureHandlers() throws Exception {
		this.defaultHandler = new DefaultHandler();
		this.contexts = (ContextHandlerCollection) theServer
			.getChildHandlerByClass(ContextHandlerCollection.class);
		if (this.contexts == null) {
			this.contexts = new ContextHandlerCollection();
			this.handlers = (HandlerCollection) theServer
			.getChildHandlerByClass(HandlerCollection.class);
			if (this.handlers == null) {
				this.handlers = new HandlerCollection();
				theServer.setHandler(handlers);
				this.handlers.setHandlers(new Handler[] { this.contexts,
						this.defaultHandler });
			} else {
				this.handlers.addHandler(this.contexts);
			}
		}
	}

	protected AbstractConnector createSecureConnector(int port, String host) 
			throws KeyStoreException, IOException {
		X509CertChainValidator validator = new KeystoreCertChainValidator(KEYSTORE, 
			KEYSTORE_P.toCharArray(), "JKS", -1);
		X509Credential credential = new KeystoreCredential(KEYSTORE, 
			KEYSTORE_P.toCharArray(), KEYSTORE_P.toCharArray(), null, "JKS");
		SslSocketConnector ssl = new CustomSslSocketConnector(
			validator, credential);
		ssl.setPort(port);
		ssl.setHost(host);
		ssl.setNeedClientAuth(true);
		ssl.setSoLingerTime(soLinger);
		return ssl;
	}

	public void addServlet(String servlet, String path) throws Exception {
		root.addServlet(Class.forName(servlet), path);
	}

	public Context getRootContext() {
		return root;
	}

	public String getUrl() {
		return url;
	}

	public String getSecUrl() {
		return secUrl;
	}

	public Server getServer() {
		return theServer;
	}
}

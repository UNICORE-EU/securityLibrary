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

import java.net.URL;
import java.util.HashMap;
import java.util.Properties;

import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.servlet.ServletContextHandler;

import eu.unicore.security.canl.AuthnAndTrustProperties;
import eu.unicore.security.canl.CredentialProperties;
import eu.unicore.security.canl.DefaultAuthnAndTrustConfiguration;
import eu.unicore.security.canl.IAuthnAndTrustConfiguration;
import eu.unicore.security.canl.TruststoreProperties;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.jetty.JettyLogger;
import eu.unicore.util.jetty.JettyProperties;
import eu.unicore.util.jetty.JettyServerBase;


/**
 * a Jetty server hosting an xfire servlet
 * 
 * @author golbi
 */
public class JettyServer4Testing extends JettyServerBase {
	public static final String KEYSTORE = "src/test/resources/client/httpserver.jks";
	public static final String KEYSTORE_P = "the!server";
	
	protected static final HashMap<String, Integer> defaults = new HashMap<String, Integer>();

	
	public JettyServer4Testing(URL[] listenUrls, IAuthnAndTrustConfiguration secProperties,
			JettyProperties extraSettings) throws ConfigurationException
	{
		super(listenUrls, secProperties, extraSettings, JettyLogger.class);
		initServer();
	}

	public static Properties getSecureProperties()
	{
		Properties p = new Properties();
		p.setProperty("j." + JettyProperties.FAST_RANDOM, "true");
		
		p.setProperty("k." + CredentialProperties.PROP_LOCATION, KEYSTORE);
		p.setProperty("k." + CredentialProperties.PROP_FORMAT, "JKS");
		p.setProperty("k." + CredentialProperties.PROP_PASSWORD, KEYSTORE_P);
		p.setProperty("t." + TruststoreProperties.PROP_TYPE, 
				TruststoreProperties.TruststoreType.keystore.toString());
		p.setProperty("t." + TruststoreProperties.PROP_KS_PATH, KEYSTORE);
		p.setProperty("t." + TruststoreProperties.PROP_KS_TYPE, "JKS");
		p.setProperty("t." + TruststoreProperties.PROP_KS_PASSWORD, KEYSTORE_P);
		p.setProperty("t." + TruststoreProperties.PROP_UPDATE, "-1");
		return p;
	}
	
	public static JettyServer4Testing getInstance(Properties p, int port, int soLinger) throws Exception {
		String host = "127.0.0.1";
		URL[] urls = new URL[] {new URL("http://" + host + ":" + port),
				new URL("https://" + host + ":" + (port+1))};
	
		AuthnAndTrustProperties secCfg = new AuthnAndTrustProperties(p, "t.", "k.");
		JettyProperties extra = new JettyProperties(p, "j.");
		return new JettyServer4Testing(urls, secCfg, extra);
	}
	
	public static JettyServer4Testing getInstance(int soLinger) throws Exception {
		int port = 62407;
		Properties p = getSecureProperties();
		p.setProperty("j." + JettyProperties.SO_LINGER_TIME, soLinger+"");
		return getInstance(p, port, soLinger);
	}
	
	public static JettyServer4Testing getAnyPortInstance(int soLinger) throws Exception {
		int port = 0;
		String host = "127.0.0.1";
		URL[] urls = new URL[] {new URL("http://" + host + ":" + port)};
		Properties p = new Properties();
		p.setProperty("j." + JettyProperties.SO_LINGER_TIME, soLinger+"");
		p.setProperty("j." + JettyProperties.FAST_RANDOM, "true");
		
		IAuthnAndTrustConfiguration secCfg = new DefaultAuthnAndTrustConfiguration();
		JettyProperties extra = new JettyProperties(p, "j.");
		return new JettyServer4Testing(urls, secCfg, extra);
	}

	@Override
	protected ContextHandler createRootHandler() throws ConfigurationException
	{
		return new ServletContextHandler(getServer(), "/", ServletContextHandler.SESSIONS);		
	}

	public String getUrl() {
		return "http://" + getServer().getConnectors()[0].getHost() + ":" + 
				getServer().getConnectors()[0].getPort();
	}

	public String getSecUrl() {
		return "https://" + getServer().getConnectors()[1].getHost() + ":" + 
				getServer().getConnectors()[1].getPort();
	}

	public void addServlet(String servlet, String path) throws Exception {
		((ServletContextHandler)getRootHandler()).addServlet(servlet, path);
	}
	
	public IAuthnAndTrustConfiguration getSecSettings() {
		return securityConfiguration;
	}
}

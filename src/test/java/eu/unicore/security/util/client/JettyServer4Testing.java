package eu.unicore.security.util.client;

import java.net.URL;
import java.util.HashMap;
import java.util.Properties;

import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.ServerConnector;

import eu.unicore.security.canl.AuthnAndTrustProperties;
import eu.unicore.security.canl.CredentialProperties;
import eu.unicore.security.canl.DefaultAuthnAndTrustConfiguration;
import eu.unicore.security.canl.IAuthnAndTrustConfiguration;
import eu.unicore.security.canl.TruststoreProperties;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.jetty.HttpServerProperties;
import eu.unicore.util.jetty.JettyServerBase;


/**
 * a Jetty server hosting an servlet handler
 * 
 * @author golbi
 */
public class JettyServer4Testing extends JettyServerBase {
	public static final String KEYSTORE = "src/test/resources/client/httpserver.jks";
	public static final String KEYSTORE_P = "the!server";
	
	protected static final HashMap<String, Integer> defaults = new HashMap<String, Integer>();

	
	public JettyServer4Testing(URL[] listenUrls, IAuthnAndTrustConfiguration secProperties,
			HttpServerProperties extraSettings) throws ConfigurationException
	{
		super(listenUrls, secProperties, extraSettings);
		initServer();
	}

	public static Properties getSecureProperties()
	{
		Properties p = new Properties();
		p.setProperty("j." + HttpServerProperties.FAST_RANDOM, "true");
		
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
	
	public static JettyServer4Testing getInstance(Properties p, int port) throws Exception {
		String host = "127.0.0.1";
		URL[] urls = new URL[] {new URL("http://" + host + ":" + port),
				new URL("https://" + host + ":" + (port+1))};
	
		AuthnAndTrustProperties secCfg = new AuthnAndTrustProperties(p, "t.", "k.");
		HttpServerProperties extra = new HttpServerProperties(p, "j.");
		return new JettyServer4Testing(urls, secCfg, extra);
	}
	
	public static JettyServer4Testing getInstance() throws Exception {
		int port = 62407;
		Properties p = getSecureProperties();
		return getInstance(p, port);
	}
	
	public static JettyServer4Testing getAnyPortInstance() throws Exception {
		int port = 0;
		String host = "127.0.0.1";
		URL[] urls = new URL[] {new URL("http://" + host + ":" + port)};
		Properties p = new Properties();
		p.setProperty("j." + HttpServerProperties.FAST_RANDOM, "true");
		
		IAuthnAndTrustConfiguration secCfg = new DefaultAuthnAndTrustConfiguration();
		HttpServerProperties extra = new HttpServerProperties(p, "j.");
		return new JettyServer4Testing(urls, secCfg, extra);
	}

	@Override
	protected Handler createRootHandler() throws ConfigurationException
	{
		return new ServletContextHandler("/", ServletContextHandler.SESSIONS);
	}

	public String getUrl() {
		return "http://" + ((ServerConnector)getServer().getConnectors()[0]).getHost() + ":" + 
				((ServerConnector)getServer().getConnectors()[0]).getPort();
	}

	public String getSecUrl() {
		return "https://" + ((ServerConnector)getServer().getConnectors()[1]).getHost() + ":" + 
				((ServerConnector)getServer().getConnectors()[1]).getPort();
	}

	public void addServlet(String servlet, String path) throws Exception {
		((ServletContextHandler)getRootHandler()).addServlet(servlet, path);
	}
	
	public IAuthnAndTrustConfiguration getSecSettings() {
		return securityConfiguration;
	}
}

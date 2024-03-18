/**
 * Copyright (c) 2005, Forschungszentrum Juelich
 * 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met: 
 * 
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name of the Forschungszentrum Juelich nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package eu.unicore.util.jetty;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.Logger;

import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.DocumentationReferenceMeta;
import eu.unicore.util.configuration.PropertiesHelper;
import eu.unicore.util.configuration.PropertyMD;
import eu.unicore.util.configuration.PropertyMD.DocumentationCategory;

/**
 * Defines constants and defaults for HTTP server (i.e. Jetty) settings, so simplifies 
 * properties handling for Jetty server setup.
 * <p>
 * Note that as Jetty configuration is simplistic (all settings can be derived directly
 * from the properties source) there is no need to define a specialized interface
 * and bean classes as other, more complicated configuration providers in this module do.  
 * @author K. Benedyczak
 */
public class HttpServerProperties extends PropertiesHelper
{
	private static final Logger log = Log.getLogger(Log.CONFIGURATION, HttpServerProperties.class);
	

	public enum XFrameOptions {
		deny("DENY"), sameOrigin("SAMEORIGIN"), allowFrom("ALLOW-FROM"), allow("");
		
		private String httpValue;
		
		XFrameOptions(String httpValue)
		{
			this.httpValue = httpValue;
		}
		
		public String toHttp()
		{
			return httpValue;
		}
	};
	
	public static final String DEFAULT_PREFIX = "httpServer.";
	
	/**
	 * use java.util.Random to generate session ids instead of SecureRandom (for SSL sockets)
	 */
	public static final String FAST_RANDOM = "fastRandom";

	/**
	 * minimum number of threads to have in the Jetty thread pool
	 */
	public static final String MIN_THREADS = "minThreads";

	/**
	 * maximum number of threads to have in the Jetty thread pool
	 */
	public static final String MAX_THREADS = "maxThreads";

	/**
	 * maximum number of incoming connections (0 = no limit)
	 */
	public static final String MAX_CONNECTIONS = "maxConnections";

	/**
	 * time (in ms.) before an idle connection will time out
	 */
	public static final String MAX_IDLE_TIME = "maxIdleTime";

	/**
	 * Whether the SSL socket accept client-side authentication
	 */
	public static final String WANT_CLIENT_AUTHN = "wantClientAuthn";

	/**
	 * Whether the SSL socket require client-side authentication
	 */
	public static final String REQUIRE_CLIENT_AUTHN = "requireClientAuthn";

	/**
	 * Space separated list of SSL cipher suites to be disabled
	 */
	public static final String DISABLED_CIPHER_SUITES = "disabledCipherSuites";

	/**
	 * Space separated list of SSL protocols to be disabled
	 */
	public static final String DISABLED_PROTOCOLS = "disabledProtocols";

	/**
	 * Prefix for the below defined gzip properties
	 */
	public static final String GZIP_PREFIX = "gzip.";
	
	/**
	 * What is the minimal size of message that should be compressed
	 */
	public static final String MIN_GZIP_SIZE = GZIP_PREFIX + "minGzipSize";
	
	/**
	 * Whether to enable compression?
	 */
	public static final String ENABLE_GZIP = GZIP_PREFIX + "enable";
	
	public static final String ENABLE_HSTS = "enableHsts";
	public static final String FRAME_OPTIONS = "xFrameOptions";
	public static final String ALLOWED_TO_EMBED = "xFrameAllowed";
	
	/**
	 * CORS support. For the parameters see 
	 * https://www.eclipse.org/jetty/documentation/9.4.x/cross-origin-filter.html
	 */
	public static final String ENABLE_CORS = "enableCORS";
	public static final String CORS_ALLOWED_ORIGINS = "CORS_allowedOrigins";
	public static final String CORS_ALLOWED_METHODS = "CORS_allowedMethods";
	public static final String CORS_ALLOWED_HEADERS = "CORS_allowedHeaders";
	public static final String CORS_EXPOSED_HEADERS = "CORS_exposedHeaders";
	public static final String CORS_CHAIN_PREFLIGHT = "CORS_chainPreflight";
	

	// enables more strict hostname checking e.g. no "localhost"
	public static final String ENABLE_SNI = "enableSNI";
	
	@DocumentationReferenceMeta
	protected final static Map<String, PropertyMD> defaults = new HashMap<>();
	
	static{
		DocumentationCategory _general= new DocumentationCategory("General settings", "1");
		DocumentationCategory _cors = new DocumentationCategory("CORS settings", "7");
		DocumentationCategory _advanced = new DocumentationCategory("Advanced settings", "9");
		
		defaults.put(MAX_THREADS, new PropertyMD("255").setCategory(_general).
				setDescription("Maximum number of threads to have in the thread pool for processing HTTP connections."
						+ " Note that this number will be increased with few additional threads to handle connectors."));
		defaults.put(MIN_THREADS, new PropertyMD("1").setPositive().setCategory(_general).
				setDescription("Minimum number of threads to have in the thread pool for processing HTTP connections. "
						+ " Note that this number will be increased with few additional threads to handle connectors."));
		defaults.put(MAX_CONNECTIONS, new PropertyMD("0").setNonNegative().setCategory(_general).
				setDescription("Maximum number of incoming connections to this server. If set to a value larger than 0, "
						+ "incoming connections will be limited to that number. Default is 0 = unlimited."));
		defaults.put(MAX_IDLE_TIME, new PropertyMD("200000").setPositive().setCategory(_general).
				setDescription("Time (in ms.) before an idle connection will time out. It should be large enough not to expire connections with slow clients, values below 30s are getting quite risky."));
		defaults.put(FAST_RANDOM, new PropertyMD("false").setCategory(_advanced).
				setDescription("Use insecure, but fast pseudo random generator to generate SSL session ids."));
		defaults.put(WANT_CLIENT_AUTHN, new PropertyMD("true").setCategory(_general).
				setDescription("Controls whether the SSL socket accepts (but does not require) client-side authentication."));
		defaults.put(REQUIRE_CLIENT_AUTHN, new PropertyMD("true").setCategory(_general).
				setDescription("Controls whether the SSL socket requires client-side authentication."));
		defaults.put(DISABLED_CIPHER_SUITES, new PropertyMD("").setCategory(_advanced).
				setDescription("Space separated list of SSL cipher suites to be disabled. "
				+ "The cipher names are documented at: "
				+ "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#sslcontext-algorithms"));
		defaults.put(DISABLED_PROTOCOLS, new PropertyMD("TLSv1.1 TLSv1").setCategory(_advanced).
				setDescription("Space separated list of protocol variants to be disabled. "
				+ "The protocol names are documened under 'Protocol Parameters' at "
				+ "https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#jsse-cipher-suite-names"));

		defaults.put(MIN_GZIP_SIZE, new PropertyMD("100000").setCategory(_advanced).
				setDescription("Specifies the minimal size of message that should be compressed."));
		defaults.put(ENABLE_GZIP, new PropertyMD("false").setCategory(_advanced).
				setDescription("Controls whether to enable compression of HTTP responses."));
		
		defaults.put(ENABLE_HSTS, new PropertyMD("false").setCategory(_advanced).
				setDescription("Control whether HTTP strict transport security is enabled. "
						+ "It is a good and strongly suggested security mechanism for all production sites. "
						+ "At the same time it can not be used with self-signed or not "
						+ "issued by a generally trusted CA server certificates, "
						+ "as with HSTS a user can't opt in to enter such site."));
		defaults.put(FRAME_OPTIONS, new PropertyMD(XFrameOptions.deny).setCategory(_advanced).
				setDescription("Defines whether a clickjacking prevention should be turned on, by insertion"
						+ "of the X-Frame-Options HTTP header. The 'allow' value disables the feature."
						+ " See the RFC 7034 for details. Note that for the 'allowFrom' "
						+ "you should define also the " + ALLOWED_TO_EMBED + 
						" option and it is not fully supported by all the browsers."));
		defaults.put(ALLOWED_TO_EMBED, new PropertyMD("http://localhost").setCategory(_advanced).
				setDescription("URI origin that is allowed to embed web interface inside a (i)frame."
						+ " Meaningful only if the " + FRAME_OPTIONS + " is set to 'allowFrom'."
						+ " The value should be in the form: 'http[s]://host[:port]'"));
				defaults.put(ENABLE_CORS, new PropertyMD("false").setCategory(_cors).
				setDescription("Control whether Cross-Origin Resource Sharing is enabled. "
						+ "Enable to allow e.g. accesing REST services from client-side JavaScript."));
		defaults.put(CORS_ALLOWED_ORIGINS, new PropertyMD("*").setCategory(_cors).
				setDescription("CORS: allowed script origins."));
		defaults.put(CORS_ALLOWED_METHODS, new PropertyMD("GET,PUT,POST,DELETE,HEAD").setCategory(_cors).
				setDescription("CORS: comma separated list of allowed HTTP verbs."));
		defaults.put(CORS_ALLOWED_HEADERS, new PropertyMD("*").setCategory(_cors).
				setDescription("CORS: comma separated list of allowed HTTP headers (default: any)"));
		defaults.put(CORS_EXPOSED_HEADERS, new PropertyMD("Location,Content-Type").setCategory(_cors).
				setDescription("CORS: comma separated list of HTTP headers that are allowed to be exposed to the client."));
		defaults.put(CORS_CHAIN_PREFLIGHT, new PropertyMD("false").setCategory(_cors).
				setDescription("CORS: whether preflight OPTION requests are chained (passed on) to the resource or handled via the CORS filter."));
		defaults.put(ENABLE_SNI, new PropertyMD("false").setCategory(_advanced).
				setDescription("Enable Server Name Indication (SNI)"));
	}

	public HttpServerProperties() throws ConfigurationException 
	{
		this(new Properties(), DEFAULT_PREFIX);
	}
	
	public HttpServerProperties(Properties properties) throws ConfigurationException 
	{
		this(properties, DEFAULT_PREFIX);
	}
	
	public HttpServerProperties(Properties properties, String prefix) throws ConfigurationException 
	{
		super(prefix, properties, defaults, log);
	}
	
	protected HttpServerProperties(Properties properties, String prefix, Map<String, PropertyMD> defaults) 
			throws ConfigurationException 
	{
		super(prefix, properties, defaults, log);
	}
	
	
	/**
	 * @return Jetty settings useful for tests, with insecure random
	 */
	public static HttpServerProperties getSimpleTestSettings()
	{
		Properties p = new Properties();
		HttpServerProperties ret = new HttpServerProperties(p);
		ret.setProperty(HttpServerProperties.FAST_RANDOM, "true");
		return ret;
	}
}






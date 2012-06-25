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

package eu.unicore.security.util.jetty;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;

import eu.unicore.util.Log;
import eu.unicore.util.configuration.ConfigurationException;
import eu.unicore.util.configuration.DocumentationReferenceMeta;
import eu.unicore.util.configuration.PropertiesHelper;
import eu.unicore.util.configuration.PropertyMD;

/**
 * Defines constants and defaults for Jetty settings, so simplifies properties handling
 * for Jetty server setup.
 * <p>
 * Note that as Jetty configuration is simplistic (all settings can be derived directly
 * from the properties source) there is no need to define a specialized interface
 * and bean classes as other, more complicated configuration providers in this module do.  
 * @author K. Benedyczak
 */
public class JettyProperties extends PropertiesHelper
{
	private static final Logger log = Log.getLogger(Log.HTTP_SERVER, JettyProperties.class);
	
	public static final String DEFAULT_PREFIX = "jetty.";
	
	/**
	 * use java.util.Random to generate session ids instead of SecureRandom (for SSL sockets)
	 */
	public static final String FAST_RANDOM = "fastRandom";

	/**
	 * Should the NIO connector be used?
	 * NIO is best suited under high-load, when lots of connections
	 * exist that are idle for long periods.
	 */
	public static final String USE_NIO = "useNIO";
	
	/**
	 * minimum number of threads to have in the Jetty thread pool
	 */
	public static final String MIN_THREADS = "minThreads";

	/**
	 * maximum number of threads to have in the Jetty thread pool
	 */
	public static final String MAX_THREADS = "maxThreads";

	/**
	 * If the number of connections exceeds this amount, then connector is put into a special 
	 * "low on resources" state. Existing connections will be closed faster. 
	 */
	public static final String HIGH_LOAD_CONNECTIONS = "highLoadConnections";

	/**
	 * time (in ms.) before an idle connection will time out
	 */
	public static final String MAX_IDLE_TIME = "maxIdleTime";

	/**
	 * in low resource conditions, time (in ms.) before an idle connection will time out
	 * @see #LOW_THREADS
	 */
	public static final String LOW_RESOURCE_MAX_IDLE_TIME = "lowResourceMaxIdleTime";

	/**
	 * Socket linger time
	 */
	public static final String SO_LINGER_TIME = "soLingerTime";

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
	
	@DocumentationReferenceMeta
	protected final static Map<String, PropertyMD> defaults=new HashMap<String, PropertyMD>();
	
	static{
		defaults.put(MAX_THREADS, new PropertyMD("255").setPositive().
				setDescription("Maximum number of threads to have in the Jetty thread pool. Threads are used to serve connections."));
		defaults.put(MIN_THREADS, new PropertyMD("1").setPositive().
				setDescription("Minimum number of threads to have in the Jetty thread pool. Threads are used to serve connections."));
		defaults.put(HIGH_LOAD_CONNECTIONS, new PropertyMD("200").setPositive().
				setDescription("If the number of connections exceeds this amount, then connector is put into a special 'low on resources' state. Existing connections will be closed faster. Note that this value is honored only for NIO connectors. Legacy connectors go into low resources mode when no more threads are available."));
		defaults.put(MAX_IDLE_TIME, new PropertyMD("3000").setPositive().
				setDescription("Time (in ms.) before an idle connection will time out"));
		defaults.put(LOW_RESOURCE_MAX_IDLE_TIME, new PropertyMD("100").setPositive().
				setDescription("In low resource conditions, time (in ms.) before an idle connection will time out."));
		defaults.put(FAST_RANDOM, new PropertyMD("false").
				setDescription("Use insecure, but fast pseudo random generator to generate session ids instead of slow and secure generator for SSL sockets. Useful for testing."));
		defaults.put(SO_LINGER_TIME, new PropertyMD("-1").
				setDescription("Socket linger time."));
		defaults.put(WANT_CLIENT_AUTHN, new PropertyMD("true").
				setDescription("Controls whether the SSL socket accepts client-side authentication."));
		defaults.put(REQUIRE_CLIENT_AUTHN, new PropertyMD("true").
				setDescription("Controls whether the SSL socket requires client-side authentication."));
		defaults.put(DISABLED_CIPHER_SUITES, new PropertyMD("").
				setDescription("Space separated list of SSL cipher suites to be disabled."));
		defaults.put(MIN_GZIP_SIZE, new PropertyMD("100000").
				setDescription("Specifies the minimal size of message that should be compressed."));
		defaults.put(ENABLE_GZIP, new PropertyMD("false").
				setDescription("Controls whether to enable compression of HTTP responses."));
		defaults.put(USE_NIO, new PropertyMD("false").
				setDescription("Controls whether the NIO connector be used. NIO is best suited under high-load, when lots of connections exist that are idle for long periods."));
	}

	public JettyProperties() throws ConfigurationException 
	{
		this(new Properties(), DEFAULT_PREFIX);
	}
	
	public JettyProperties(Properties properties) throws ConfigurationException 
	{
		this(properties, DEFAULT_PREFIX);
	}
	
	public JettyProperties(Properties properties, String prefix) throws ConfigurationException 
	{
		super(prefix, properties, defaults, log);
	}
	
	protected JettyProperties(Properties properties, String prefix, Map<String, PropertyMD> defaults) 
			throws ConfigurationException 
	{
		super(prefix, properties, defaults, log);
	}
}






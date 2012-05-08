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

import eu.unicore.security.util.ConfigurationException;
import eu.unicore.security.util.Log;
import eu.unicore.security.util.PropertiesHelper;
import eu.unicore.security.util.PropertyMD;

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
	 * default: true
	 */
	public static final String FAST_RANDOM = "fastRandom";

	/**
	 * Should the NIO connector be used?
	 * NIO is best suited under high-load, when lots of connections
	 * exist that are idle for long periods.
	 * 
	 * default: false
	 */
	public static final String USE_NIO = "useNIO";
	
	/**
	 * minimum number of threads to have in the Jetty thread pool (default: 1)
	 */
	public static final String MIN_THREADS = "minThreads";

	/**
	 * maximum number of threads to have in the Jetty thread pool (default: 255)
	 */
	public static final String MAX_THREADS = "maxThreads";

	/**
	 * lowThreads is a threshold indicator.  If the available number 
	 * of threads in the pool dips under this value (especially when max 
	 * threads is reached), per connection max idle time will be cut 
	 * from normal to low-resource
	 * (default: 50)
	 */
	public static final String LOW_THREADS = "lowThreads";

	/**
	 * time (in ms.) before an idle connection will time out (default: 3000)
	 */
	public static final String MAX_IDLE_TIME = "maxIdleTime";

	/**
	 * in low resource conditions, time (in ms.) before an idle connection will time out (default: 100)
	 * @see #LOW_THREADS
	 */
	public static final String LOW_RESOURCE_MAX_IDLE_TIME = "lowResourceMaxIdleTime";

	/**
	 * Socket linger time default: not set
	 */
	public static final String SO_LINGER_TIME = "soLingerTime";

	/**
	 * Whether the SSL socket accept client-side authentication (default: true)
	 */
	public static final String WANT_CLIENT_AUTHN = "wantClientAuthn";

	/**
	 * Whether the SSL socket require client-side authentication (default: true)
	 */
	public static final String REQUIRE_CLIENT_AUTHN = "requireClientAuthn";

	/**
	 * Space separated list of SSL cipher suites to be disabled (default: empty)
	 */
	public static final String DISABLED_CIPHER_SUITES = "disabledCipherSuites";

	/**
	 * Prefix for the below defined gzip properties
	 */
	public static final String GZIP_PREFIX = "gzip.";
	
	/**
	 * What is the minimal size of message that should be compressed (default: 100000)
	 */
	public static final String MIN_GZIP_SIZE = GZIP_PREFIX + "minGzipSize";
	
	/**
	 * Whether to enable compression? (default: false)
	 */
	public static final String ENABLE_GZIP = GZIP_PREFIX + "enable";
	
	protected final static Map<String, PropertyMD> defaults=new HashMap<String, PropertyMD>();
	
	static{
		defaults.put(MAX_THREADS, new PropertyMD("255").setPositive());
		defaults.put(MIN_THREADS, new PropertyMD("1").setPositive());
		defaults.put(LOW_THREADS, new PropertyMD("50").setPositive());
		defaults.put(MAX_IDLE_TIME, new PropertyMD("3000").setPositive());
		defaults.put(LOW_RESOURCE_MAX_IDLE_TIME, new PropertyMD("100").setPositive());
		defaults.put(FAST_RANDOM, new PropertyMD("false"));
		defaults.put(SO_LINGER_TIME, new PropertyMD("-1"));
		defaults.put(WANT_CLIENT_AUTHN, new PropertyMD("true"));
		defaults.put(REQUIRE_CLIENT_AUTHN, new PropertyMD("true"));
		defaults.put(DISABLED_CIPHER_SUITES, new PropertyMD(""));
		defaults.put(MIN_GZIP_SIZE, new PropertyMD("100000"));
		defaults.put(ENABLE_GZIP, new PropertyMD("false"));
		defaults.put(USE_NIO, new PropertyMD("false"));
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






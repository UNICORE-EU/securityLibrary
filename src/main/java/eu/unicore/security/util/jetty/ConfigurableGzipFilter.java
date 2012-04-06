package eu.unicore.security.util.jetty;

import java.util.Enumeration;

import javax.servlet.FilterConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;

import org.mortbay.servlet.GzipFilter;

import eu.unicore.security.util.ConfigurationException;

/**
 * wrapper around Jetty's {@link GzipFilter} that allows configuration
 * using {@link JettyProperties} <br/>
 * 
 * The following configuration options exist.
 * 
 * <ul>
 * <li>gateway.jetty.gzip.minGzipSize  The minimum size of a data chunk that is gzipped (default: 65535</li>
 * <li>gateway.jetty.gzip.bufferSize  The size of the buffer used for gzipping (default: 8192)</li>
 * </ul>
 * 
 * @author schuller
 */
public class ConfigurableGzipFilter extends GzipFilter
{	
	private JettyProperties properties;
	
	public ConfigurableGzipFilter(JettyProperties properties)
	{
		this.properties = properties;
	}
	
	public void init(FilterConfig filterConfig) throws ServletException
	{
		_minGzipSize=65535;
		super.init(new MyFilterConfig(filterConfig));
	}

	private class MyFilterConfig implements FilterConfig{
		private FilterConfig config;
		
		public MyFilterConfig(FilterConfig config){
			this.config=config;
		}
		public String getFilterName() {
			return config.getFilterName();
		}
		public String getInitParameter(String name) {
			String val=config.getInitParameter(name);
			if(val==null)
				try
				{
					val=properties.getValue(JettyProperties.GZIP_PREFIX + name);
				} catch (ConfigurationException e)
				{
					throw new RuntimeException(
						"BUG: got no value (even default) for: " + name, e);
				}
			return val;
		}
		public Enumeration<?> getInitParameterNames() {
			return config.getInitParameterNames();
		}
		public ServletContext getServletContext() {
			return config.getServletContext();
		}
	}
}

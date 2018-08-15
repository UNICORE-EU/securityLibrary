package eu.unicore.util.jetty;

import org.apache.log4j.Level;
import org.eclipse.jetty.util.log.AbstractLogger;
import org.eclipse.jetty.util.log.Logger;

import eu.unicore.util.Log;

/**
 * Route Jetty logging through log4j using a predefined {@link Log#CONNECTIONS}
 * category. If you want to change the category extend this class. The default
 * constructor must be always present.
 * 
 * @author schuller
 * @author golbi
 */
public class JettyLogger extends AbstractLogger implements Logger
{

	private final org.apache.log4j.Logger log;
	private Level configuredLevel;

	public JettyLogger()
	{
		this(null);
	}

	public JettyLogger(String name)
	{
		if (name == null)
			name = getDefaultLog4jLoggerName();
		log = org.apache.log4j.Logger.getLogger(name);
		configuredLevel = log.getLevel();
	}

	/**
	 * Override this method to create a non-default logger.
	 */
	protected String getDefaultLog4jLoggerName()
	{
		return Log.HTTP_SERVER + "." + JettyLogger.class.getSimpleName();
	}


	public String getName()
	{
		return log.getName();
	}

	public void warn(String msg, Object... args)
	{
		log.warn(format(msg, args));
	}

	public void warn(Throwable thrown)
	{
		warn("", thrown);
	}

	public void warn(String msg, Throwable thrown)
	{
		log.warn(msg, thrown);
	}

	public void info(String msg, Object... args)
	{
		log.info(format(msg, args));
	}

	public void info(Throwable thrown)
	{
		info("", thrown);
	}

	public void info(String msg, Throwable thrown)
	{
		log.info(msg, thrown);
	}

	public boolean isDebugEnabled()
	{
		return log.isDebugEnabled();
	}

	public void setDebugEnabled(boolean enabled)
	{
		if (enabled)
		{
			configuredLevel = log.getLevel();
			log.setLevel(Level.DEBUG);
		} else
		{
			log.setLevel(configuredLevel);
		}
	}

	public void debug(String msg, Object... args)
	{
		if(log.isDebugEnabled()){
			log.debug(format(msg, args));
		}
	}

	public void debug(Throwable thrown)
	{
		debug("", thrown);
	}

	public void debug(String msg, Throwable thrown)
	{
		log.debug(msg, thrown);
	}

	/**
	 * Create a Child Logger of this Logger.
	 */
	protected Logger newLogger(String fullname)
	{
		return new JettyLogger(fullname);
	}

	public void ignore(Throwable ignored)
	{
	}

	private String format(String msg, Object... args)
	{
		msg = String.valueOf(msg); // Avoids NPE
		String braces = "{}";
		StringBuilder builder = new StringBuilder();
		int start = 0;
		for (Object arg : args)
		{
			int bracesIndex = msg.indexOf(braces, start);
			if (bracesIndex < 0)
			{
				builder.append(msg.substring(start));
				builder.append(" ");
				builder.append(arg);
				start = msg.length();
			} else
			{
				builder.append(msg.substring(start, bracesIndex));
				builder.append(String.valueOf(arg));
				start = bracesIndex + braces.length();
			}
		}
		builder.append(msg.substring(start));
		return builder.toString();
	}
}

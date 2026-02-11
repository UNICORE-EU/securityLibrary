package eu.unicore.util;

import org.apache.logging.log4j.Logger;

/**
 * This interface implementation can be used to change the default Logger 
 * creation logic from the {@link Log} class. 
 * @author K. Benedyczak
 */
public interface LoggerFactory
{
	public static final String LOGGER_FACTORY_PROPERTY = Log.class.getName()+".loggerFactory";

	/**
	 * returns a logger name, using the given prefix and the simple name
	 * of the given class
	 * 
	 * @param prefix - the prefix to use
	 * @param clazz - the class
	 * @return logger name
	 */
	public String getLoggerName(String prefix, Class<?>clazz);
	
	/**
	 * returns a logger, using the given prefix and the simple name
	 * of the given class
	 * 
	 * @param prefix - the prefix to use
	 * @param clazz - the class
	 * @return logger
	 */
	public Logger getLogger(String prefix, Class<?>clazz);

	/**
	 * returns a logger, using the given logger name
	 * @param name - the logger name
	 * @return logger
	 */
	public Logger getLogger(String name);
}

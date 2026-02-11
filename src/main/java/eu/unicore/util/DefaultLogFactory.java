package eu.unicore.util;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

/**
 * Default {@link LoggerFactory} - creates logger from the given prefix (as-is) and simple class name.
 * @author K. Benedyczak
 */
public class DefaultLogFactory implements LoggerFactory
{
	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getLoggerName(String prefix, Class<?>clazz){
		return prefix+"."+clazz.getSimpleName();
	}
	
	/**
	 * {@inheritDoc}
	 */
	@Override
	public Logger getLogger(String prefix, Class<?>clazz){
		return LogManager.getLogger(getLoggerName(prefix, clazz));
	}

	@Override
	public Logger getLogger(String name){
		return LogManager.getLogger(name);
	}
}

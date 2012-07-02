/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util;

import org.apache.log4j.Logger;

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
		return Logger.getLogger(getLoggerName(prefix, clazz));
	}
}

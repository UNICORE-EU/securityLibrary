/*
 * Copyright (c) 2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
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
	
	public org.apache.log4j.Logger get12Logger(String prefix, Class<?>clazz){
		return org.apache.log4j.LogManager.getLogger(getLoggerName(prefix, clazz));
	}
}

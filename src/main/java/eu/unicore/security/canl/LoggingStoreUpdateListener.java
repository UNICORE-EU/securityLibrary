/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.security.canl;

import org.apache.log4j.Logger;

import eu.emi.security.authn.x509.StoreUpdateListener;
import eu.unicore.util.Log;

/**
 * Logs loudly problems with store updates and on debug level normal events.
 * @author K. Benedyczak
 */
public class LoggingStoreUpdateListener implements StoreUpdateListener
{
	private static final Logger log = Log.getLogger(Log.SECURITY, LoggingStoreUpdateListener.class);
	
	@Override
	public void loadingNotification(String location, String type, Severity level,
			Exception cause)
	{
		StringBuilder sb = new StringBuilder();
		sb.append(type).append(" from location ").append(location);
		if (level == Severity.NOTIFICATION)
		{
			if (log.isDebugEnabled())
			{
				sb.insert(0, "Loaded ");
				log.debug(sb.toString());
			}
			return;
		} 
		
		sb.insert(0, "Problem loading ");
		if (cause != null)
		{
			sb.append(": ");
			if (Exception.class.equals(cause.getClass()) && cause.getMessage() != null)
				sb.append(cause.getMessage());
			else
				sb.append(cause.toString());
		}
		if (level == Severity.WARNING)
		{
			log.warn(sb.toString());
		} else
		{
			if (cause == null)
				log.error(sb.toString());
			else
				log.error(sb.toString(), cause);
		}
	}
}

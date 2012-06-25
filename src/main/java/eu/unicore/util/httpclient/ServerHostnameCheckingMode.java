/*
 * Copyright (c) 2011-2012 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.httpclient;

/**
 * Defines possible configuration options for checking server's certificate subject to its DNS hostname matching.
 * 
 * 
 * @author K. Benedyczak
 */
public enum ServerHostnameCheckingMode
{
	/**
	 * Checking won't be performed
	 */
	NONE, 
	
	/**
	 * Checking will be performed but a failure will only result in a message presented to the user
	 * or logged.
	 */
	WARN, 
	
	/**
	 * Checking will be performed and a failure will result in closing the connection.
	 */
	FAIL 
}

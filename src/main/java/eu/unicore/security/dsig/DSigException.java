/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 6, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.dsig;

/**
 * Generic class that is used when there is any kind of the problem with digital
 * signature creation or checking it.
 * 
 * @author K. Benedyczak
 */
public class DSigException extends Exception
{
	private static final long serialVersionUID = -3162396183055439683L;

	public DSigException(String msg, Throwable reason)
	{
		super(msg, reason);
	}

	public DSigException(Throwable reason)
	{
		super("XML digital signature problem", reason);
	}

	public DSigException(String msg)
	{
		super(msg);
	}
}

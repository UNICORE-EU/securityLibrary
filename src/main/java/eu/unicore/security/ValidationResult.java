/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security;

/**
 * Represents assertion verification result.
 * @author K. Benedyczak
 */
public class ValidationResult
{
	private boolean valid;
	private String invalidResaon;
	
	public ValidationResult(boolean valid, String invalidResaon)
	{
		super();
		this.valid = valid;
		this.invalidResaon = invalidResaon;
	}
	
	public String getInvalidResaon()
	{
		return invalidResaon;
	}
	
	public void setInvalidResaon(String invalidResaon)
	{
		this.invalidResaon = invalidResaon;
	}
	
	public boolean isValid()
	{
		return valid;
	}
	
	public void setValid(boolean valid)
	{
		this.valid = valid;
	}
}

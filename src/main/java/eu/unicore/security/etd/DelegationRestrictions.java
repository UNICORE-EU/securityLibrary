/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import java.util.Calendar;
import java.util.Date;

import org.apache.xmlbeans.XmlObject;

/**
 * @author K. Benedyczak
 */
public class DelegationRestrictions
{
	private Date notBefore;
	private Date notOnOrAfter;
	private int maxProxyCount;
	private XmlObject[] conditions;
	
	public DelegationRestrictions(Date notBefore, Date notOnOrAfter, int maxProxyCount)
	{
		this.notBefore = notBefore;
		this.notOnOrAfter = notOnOrAfter;
		this.maxProxyCount = maxProxyCount;
	}

	public DelegationRestrictions(Date notBefore, int validDays, int maxProxyCount)
	{
		this.notBefore = notBefore;
		Calendar c = Calendar.getInstance();
		if (notBefore != null)
			c.setTime(notBefore);
		c.add(Calendar.DATE, validDays);
		this.notOnOrAfter = c.getTime();
		this.maxProxyCount = maxProxyCount;
	}
	
	public int getMaxProxyCount()
	{
		return maxProxyCount;
	}
	
	public void setMaxProxyCount(int maxProxyCount)
	{
		this.maxProxyCount = maxProxyCount;
	}
	
	public Date getNotBefore()
	{
		return notBefore;
	}
	
	public void setNotBefore(Date notBefore)
	{
		this.notBefore = notBefore;
	}
	
	public Date getNotOnOrAfter()
	{
		return notOnOrAfter;
	}
	
	public void setNotOnOrAfter(Date notOnOrAfter)
	{
		this.notOnOrAfter = notOnOrAfter;
	}

	public XmlObject[] getCustomConditions()
	{
		return conditions;
	}

	public void setCustomConditions(XmlObject[] conditions)
	{
		this.conditions = conditions;
	}
}

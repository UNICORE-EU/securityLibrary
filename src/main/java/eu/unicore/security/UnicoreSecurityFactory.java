/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on May 7, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security;

import eu.unicore.security.consignor.ConsignorAPI;
import eu.unicore.security.consignor.ConsignorImpl;
import eu.unicore.security.etd.ETDApi;
import eu.unicore.security.etd.ETDImpl;

/**
 * Used to obtain various security related implementations.
 * @author K. Benedyczak
 */
public class UnicoreSecurityFactory
{
	private static ETDImpl etdImpl = null;
	private static ConsignorImpl consignorImpl = null;
	
	public static ETDApi getETDEngine()
	{
		if (etdImpl == null)
			etdImpl = new ETDImpl();
		return etdImpl;
	}
	
	public static ConsignorAPI getConsignorAPI()
	{
		if (consignorImpl == null)
			consignorImpl = new ConsignorImpl();
		return consignorImpl;
	}
}

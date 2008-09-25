/*
 * Copyright (c) 2007, 2008 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on Apr 25, 2007
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */

package eu.unicore.security.etd;

import eu.unicore.security.TestBase;
import eu.unicore.security.UnicoreSecurityFactory;


/**
 * @author K. Benedyczak
 */
public abstract class ETDTestBase extends TestBase
{
	protected ETDApi etdEngine;
	
	protected void setUp()
	{
		super.setUp();
		etdEngine = UnicoreSecurityFactory.getETDEngine();
	}
}

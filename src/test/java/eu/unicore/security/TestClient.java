/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 16-06-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security;

import junit.framework.TestCase;

public class TestClient extends TestCase
{
	public void testToString()
	{
		Client c = new Client();
		c.toString();
		c.setDistinguishedName("CN=foo");
		c.toString();
		c.setQueue(new Queue());
		c.toString();
		c.setRole(new Role());
		c.toString();
		c.setVos(new String[] {"vo1", "vo2"});
		c.toString();
		c.setXlogin(new Xlogin());
		c.toString();
		
		c.setQueue(new Queue(new String[] {"queue1", "queue2"}));
		Xlogin xlogin = new Xlogin(new String[] {"uid1", "uid2"}, 
				new String[] {"gid1", "gid2", "gid3"});
		xlogin.setSelectedLogin("uid2");
		xlogin.setSelectedSupplementaryGroups(new String[] {"gid3"});
		c.setXlogin(xlogin);
		System.out.println(c);
	}
}

package eu.unicore.security;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class TestClient
{
	@Test
	public void testToString()
	{
		Client c = new Client();
		c.toString();
		c.setLocalClient();
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
	
	@Test
	public void testAuthenticatedWithDnOnly()throws InterruptedException{
		Client c=new Client();
		SecurityTokens t=new SecurityTokens();
		t.setUserName("CN=dummy");
		t.setConsignorTrusted(true);
		c.setAuthenticatedClient(t);
		assertEquals(Client.Type.AUTHENTICATED, c.getType());
	}
}

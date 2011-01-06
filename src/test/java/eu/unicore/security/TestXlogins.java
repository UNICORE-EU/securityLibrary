package eu.unicore.security;

import junit.framework.TestCase;
import eu.unicore.security.Xlogin;

public class TestXlogins extends TestCase{

	public void testEncode(){
		Xlogin x=new Xlogin(new String[] {"foo", "bar"});
		assertEquals("foo:bar", x.getEncoded());
	}
	
	public void testEncodeSingle(){
		Xlogin x=new Xlogin(new String[] {"foo"});
		assertEquals("foo", x.getEncoded());
		assertEquals("foo", x.getUserName());
	}
	
	public void testRetrieve(){
		Xlogin x=new Xlogin(new String[] {"foo", "bar", "baz"});
		String[]xl=x.getLogins();
		assertEquals(3,xl.length);
	}
	
	public void testRetrieveDefault(){
		Xlogin x=new Xlogin(new String[] {"foo", "bar"});
		assertEquals("foo", x.getUserName());
	}
	
	public void testRetrievePreferred(){
		Xlogin x=new Xlogin(new String[] {"foo", "bar"});
		assertEquals("foo",x.getUserName());
		assertTrue(x.isValid("foo"));
		assertTrue(x.isValid("bar"));
	}
	
	/*
	 * tests for the group frunctionality
	 */
	
	public void testNoGroup(){
		Xlogin x=new Xlogin(new String[] {"foo", "bar"});
		assertEquals("foo:bar", x.getEncoded());
		assertEquals("",x.getEncodedGroups());
		assertNull(x.getGroup());
	}
	
	public void testEncodeGroups(){
		Xlogin x=new Xlogin(new String[] {"foo", "bar"}, 
				new String[] {"group1", "group2"});
		assertEquals("foo:bar", x.getEncoded());
		assertEquals("group1:group2", x.getEncodedGroups());
		
	}
	
	public void testEncodeSingleGrp(){
		Xlogin x=new Xlogin(new String[] {"foo"});
		assertEquals("foo", x.getEncoded());
		assertEquals("foo", x.getUserName());
	}

	public void testEncodeSelectedSupGroups(){
		Xlogin x=new Xlogin(new String[] {"foo", "bar"}, 
				new String[] {"group1", "group2", "group3"});
		x.setSelectedSupplementaryGroups(new String[] {"group1", "group3"});
		assertEquals("group1:group3", x.getEncodedSelectedSupplementaryGroups());
		x.setSelectedSupplementaryGroups(new String[] {});
		assertEquals("", x.getEncodedSelectedSupplementaryGroups());
	}
	
	public void testRetrieveGrp(){
		Xlogin x=new Xlogin(new String[] {"foo", "bar", "baz"}, 
				new String[] {"group1", "group2", "group3"});
		String[]gr=x.getGroups();
		assertEquals(3,gr.length);
		
	}
	
	public void testRetrieveDefaultGrp(){
		Xlogin x=new Xlogin(new String[] {"foo", "bar"},
				new String[] {"grp1", "grp2"});
		assertEquals("grp1", x.getGroup());
	}
	
/*	public void testRetrievePreferredGrp(){
		Xlogin x=new Xlogin(new String[] {"foo", "bar"},
				new String[] {"grp1", "grp2"});
		assertEquals("grp1",x.getGroup(null));
		assertEquals("grp1",x.getGroup("grp1"));
		assertEquals("grp2",x.getGroup("grp2"));
		assertEquals("grp1",x.getGroup("grp3"));
	}
*/	
}

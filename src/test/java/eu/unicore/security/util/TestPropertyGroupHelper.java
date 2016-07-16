package eu.unicore.security.util;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.junit.Test;

import eu.unicore.util.configuration.PropertyGroupHelper;

public class TestPropertyGroupHelper {

	@Test
	public void test1(){
	
		HashMap<String,String>props=new HashMap<String, String>();
		props.put("TEST_1","foo1");
		props.put("TEST_2","foo2");
		props.put("TEST_group_1","gr1");
		props.put("TEST__group_2","gr2");
		props.put("NOTME_xx","abc");
		
		
		for(int i=0;i<200;i++){
			props.put("XX_"+i,"xx"+1);
		}
		PropertyGroupHelper ah=new PropertyGroupHelper(props, "TEST_");
		Iterator<String>i=ah.keys();
		int c=0;
		while(i.hasNext() && c < props.size()*2){
			c++;
			assertTrue(i.next().startsWith("TEST_"));
		}
		assertEquals(4,c);
		
		Map<String,String>filteredProps=ah.getFilteredMap();
		assertEquals(4,filteredProps.size());
		
		filteredProps=ah.getFilteredMap("group");
		assertEquals(2,filteredProps.size());
		Iterator<String>i2=filteredProps.keySet().iterator();
		while(i2.hasNext()){
			assertTrue(i2.next().contains("group"));
		}
	}
	
	@Test
	public void iterationOverLargePropertiesSetWorksWithoutStackOverflow()
	{
		HashMap<String,String> props = new HashMap<String, String>();
		for (int i=0; i<200000; i++)
			props.put("g1.p" + i, "v");
		for (int i=0; i<2000; i++)
			props.put("g2.p" + i, "v");
		
		PropertyGroupHelper ah = new PropertyGroupHelper(props, "g2");
		int c = 0;
		Iterator<String> i = ah.keys();
		while (i.hasNext())
		{
			c++;
			assertThat(i.next().startsWith("g2."), is(true));
		}
		assertThat(c, is(2000));
	}
	
}

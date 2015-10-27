package eu.unicore.security.util.client;

import java.util.Properties;

import javax.net.ssl.SSLException;

import junit.framework.TestCase;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;

import eu.emi.security.authn.x509.helpers.BinaryCertChainValidator;
import eu.unicore.util.httpclient.ClientProperties;
import eu.unicore.util.httpclient.HttpUtils;

/**
 * tests SSL connections to "external" servers
 */
public class TestSSL extends TestCase {

	public void testExternalSSLServer() throws Exception {
		
		Properties props = new Properties();
		
		// trick the ClientProperties into not requiring
		// truststore and credentials
		props.put("client.digitalSigningEnabled","false");
		props.put("client.sslEnabled","false");
		
		ClientProperties cp = new ClientProperties(props);
		cp.setSslAuthn(false);
		cp.setSslEnabled(true);
		cp.setValidator(new BinaryCertChainValidator(true));
		
		try{
			String uri = "https://www.google.com";
			HttpClient hc = HttpUtils.createClient(uri, cp);
			HttpGet get = new HttpGet(uri);
			HttpResponse res = hc.execute(get);
			assertEquals("Error: "+res.getStatusLine(), res.getStatusLine().getStatusCode(), 200);
		}catch(Exception ex){
			// we only want to fail on SSL exceptions, as others errors might 
			// be due to the testing environment
			if(ex instanceof SSLException){
				ex.printStackTrace();
				fail("SSL error: "+ex.getMessage());
			}
			else{
				System.out.println("WARN: ignoring non-SSL exception");
				ex.printStackTrace();	
			}
		}
	}

}

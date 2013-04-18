package eu.unicore.security.util.client;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Properties;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;

import junit.framework.TestCase;

import eu.unicore.util.httpclient.DefaultClientConfiguration;
import eu.unicore.util.httpclient.HttpClientProperties;
import eu.unicore.util.httpclient.HttpUtils;

/**
 * this test requires a proxy server
 * 
 * @author schuller
 */
public class TestProxyCalls extends TestCase{

	int port;
	boolean gotCall=false;
	ServerSocket s;
	
	protected void setUp()throws InterruptedException{
		//start a fake proxy server...
		Runnable r=new Runnable(){
			public void run(){
				try{
					ServerSocket s=new ServerSocket(0);
					port=s.getLocalPort();
					s.setSoTimeout(5000);
					try{
						byte[]buf=new byte[2048];
						Socket socket=s.accept();
						gotCall=true;
						socket.getInputStream().read(buf);
						String answer="hi";
						socket.getOutputStream().write("HTTP/1.1 200 OK\nContent-Length: 2\n\n".getBytes());
						socket.getOutputStream().write(answer.getBytes());
						socket.close();
					}catch(SocketTimeoutException te){};
				}catch(Exception ex){

				}
			}
		};
		new Thread(r).start();
		Thread.sleep(2000);
	}

	@Override
	protected void tearDown(){
		try{
			if(s!=null)s.close();
		}catch(Exception ex){
			ex.printStackTrace();
		}
	}

	public void testProxyCall()throws Exception{
		HttpClientProperties props = new HttpClientProperties(new Properties());
		props.setProperty(HttpClientProperties.HTTP_PROXY_HOST, "localhost");
		props.setProperty(HttpClientProperties.HTTP_PROXY_PORT, String.valueOf(port));
		String uri="http://www.verisign.com/";
		DefaultClientConfiguration config = new DefaultClientConfiguration();
		config.setHttpClientProperties(props);
		HttpClient client=HttpUtils.createClient(uri, config);
		HttpGet httpget = new HttpGet("http://www.verisign.com/");
		try { 
			client.execute(httpget);
			assertTrue(gotCall);
		} finally {
			httpget.releaseConnection();
		}
	}


}

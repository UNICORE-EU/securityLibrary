package eu.unicore.security.util.client;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;

import eu.unicore.security.util.client.HttpUtils;

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
		Properties props = new Properties();
		props.setProperty(HttpUtils.HTTP_PROXY_HOST, "localhost");
		props.setProperty(HttpUtils.HTTP_PROXY_PORT, String.valueOf(port));
		String uri="http://www.verisign.com/";
		HttpClient client=HttpUtils.createClient(uri, new DefaultClientConfiguration(), 
				props);
		GetMethod httpget = new GetMethod("http://www.verisign.com/");
		try { 
			client.executeMethod(httpget);
			assertTrue(gotCall);
		} finally {
			httpget.releaseConnection();
		}
	}


}

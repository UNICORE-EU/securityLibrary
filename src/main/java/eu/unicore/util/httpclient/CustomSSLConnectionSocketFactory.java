package eu.unicore.util.httpclient;

import java.io.IOException;
import java.net.Socket;
import java.nio.channels.SocketChannel;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;

import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.core5.annotation.Contract;
import org.apache.hc.core5.annotation.ThreadingBehavior;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.Args;

/**
 * Slightly modified SSLConnectionSocketFactory - the original class is calling 
 * {@link SSLSocket#startHandshake()} on each connection, which  hides the
 * real exceptions with valuable information: one only gets connection reset.
 * Also, this creates selectable sockets via SocketChannel.open().getSocket()
 * @see SSLConnectionSocketFactory
 */
@Contract(threading = ThreadingBehavior.STATELESS)
public class CustomSSLConnectionSocketFactory extends SSLConnectionSocketFactory {
    
    public CustomSSLConnectionSocketFactory(final SSLContext sslContext, final HostnameVerifier hostnameVerifier) {
        super(Args.notNull(sslContext, "SSL context").getSocketFactory(),
                null, null, hostnameVerifier);
     }

    @Override
    protected void prepareSocket(final SSLSocket socket) throws IOException {
        socket.getSession().getPeerCertificates();
    }

    @Override
    public Socket createSocket(final HttpContext context) throws IOException {
        return SocketChannel.open().socket();
    }

}
package eu.unicore.util.httpclient;

import java.io.IOException;

import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;

/**
 * HttpClientResponseHandler that simply returns the "raw" {@link ClassicHttpResponse}
 *
 * @author schuller
 */
public class HttpResponseHandler implements HttpClientResponseHandler<ClassicHttpResponse>{

	public static final HttpResponseHandler INSTANCE = new HttpResponseHandler();

    @Override
    public ClassicHttpResponse handleResponse(final ClassicHttpResponse response) throws IOException {
        return response;
    }

}

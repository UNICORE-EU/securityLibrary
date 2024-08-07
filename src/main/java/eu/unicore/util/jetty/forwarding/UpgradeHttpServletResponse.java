package eu.unicore.util.jetty.forwarding;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

/**
 * from Jetty's websocket module
 */
public class UpgradeHttpServletResponse implements HttpServletResponse
{
    private static final String UNSUPPORTED = "Feature unsupported after Connection: Upgrade";

    private HttpServletResponse _response;
    private int _status;
    private Map<String, Collection<String>> _headers;
    private Locale _locale;
    private String _characterEncoding;
    private String _contentType;

    public UpgradeHttpServletResponse(HttpServletResponse response)
    {
        _response = response;
    }

    public void upgrade()
    {
        _status = _response.getStatus();
        _locale = _response.getLocale();
        _characterEncoding = _response.getCharacterEncoding();
        _contentType = _response.getContentType();
        _headers = new HashMap<>();
        for (String name : _response.getHeaderNames())
        {
            _headers.put(name, _response.getHeaders(name));
        }

        _response = null;
    }

    public HttpServletResponse getResponse()
    {
        return _response;
    }

    @Override
    public int getStatus()
    {
        if (_response == null)
            return _status;
        return _response.getStatus();
    }

    @Override
    public String getHeader(String s)
    {
        if (_response == null)
        {
            Collection<String> values = _headers.get(s);
            if (values == null)
                return null;
            return values.stream().findFirst().orElse(null);
        }

        return _response.getHeader(s);
    }

    @Override
    public Collection<String> getHeaders(String s)
    {
        if (_response == null)
            return _headers.get(s);
        return _response.getHeaders(s);
    }

    @Override
    public Collection<String> getHeaderNames()
    {
        if (_response == null)
            return _headers.keySet();
        return _response.getHeaderNames();
    }

    @Override
    public Locale getLocale()
    {
        if (_response == null)
            return _locale;
        return _response.getLocale();
    }

    @Override
    public boolean containsHeader(String s)
    {
        if (_response == null)
        {
            Collection<String> values = _headers.get(s);
            return values != null && !values.isEmpty();
        }

        return _response.containsHeader(s);
    }

    @Override
    public String getCharacterEncoding()
    {
        if (_response == null)
            return _characterEncoding;
        return _response.getCharacterEncoding();
    }

    @Override
    public String getContentType()
    {
        if (_response == null)
            return _contentType;
        return _response.getContentType();
    }

    @Override
    public void addCookie(Cookie cookie)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.addCookie(cookie);
    }

    @Override
    public String encodeURL(String s)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        return _response.encodeURL(s);
    }

    @Override
    public String encodeRedirectURL(String s)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        return _response.encodeRedirectURL(s);
    }

    @Override
    public String encodeUrl(String s)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        return _response.encodeURL(s);
    }

    @Override
    public String encodeRedirectUrl(String s)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        return _response.encodeRedirectURL(s);
    }

    @Override
    public ServletOutputStream getOutputStream() throws IOException
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        return _response.getOutputStream();
    }

    @Override
    public PrintWriter getWriter() throws IOException
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        return _response.getWriter();
    }

    @Override
    public void setCharacterEncoding(String s)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.setCharacterEncoding(s);
    }

    @Override
    public void setContentLength(int i)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.setContentLength(i);
    }

    @Override
    public void setContentLengthLong(long l)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.setContentLengthLong(l);
    }

    @Override
    public void setContentType(String s)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.setContentType(s);
    }

    @Override
    public void setBufferSize(int i)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.setBufferSize(i);
    }

    @Override
    public int getBufferSize()
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        return _response.getBufferSize();
    }

    @Override
    public void flushBuffer() throws IOException
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.flushBuffer();
    }

    @Override
    public void resetBuffer()
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.resetBuffer();
    }

    @Override
    public boolean isCommitted()
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        return _response.isCommitted();
    }

    @Override
    public void reset()
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.reset();
    }

    @Override
    public void setLocale(Locale locale)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.setLocale(locale);
    }

    @Override
    public void sendError(int sc, String msg) throws IOException
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.sendError(sc, msg);
    }

    @Override
    public void sendError(int sc) throws IOException
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.sendError(sc);
    }

    @Override
    public void setHeader(String name, String value)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.setHeader(name, value);
    }

    @Override
    public void sendRedirect(String s) throws IOException
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.sendRedirect(s);
    }

    @Override
    public void setDateHeader(String s, long l)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.setDateHeader(s, l);
    }

    @Override
    public void addDateHeader(String s, long l)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.addDateHeader(s, l);
    }

    @Override
    public void addHeader(String name, String value)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.addHeader(name, value);
    }

    @Override
    public void setIntHeader(String s, int i)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.setIntHeader(s, i);
    }

    @Override
    public void addIntHeader(String s, int i)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.addIntHeader(s, i);
    }

    @Override
    public void setStatus(int i)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.setStatus(i);
    }

    @Override
    @Deprecated
    public void setStatus(int i, String s)
    {
        if (_response == null)
            throw new UnsupportedOperationException(UNSUPPORTED);
        _response.setStatus(i, s);
    }
}

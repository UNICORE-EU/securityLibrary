/*
 * Copyright (c) 2014 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE.txt file for licensing information.
 */
package eu.unicore.util.jetty;

import java.io.IOException;
import java.io.OutputStream;

import org.eclipse.jetty.http.HttpMethod;
import org.eclipse.jetty.http.MimeTypes;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.util.ByteArrayISO8859Writer;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Handler for showing custom 404
 * 
 * @author K. Benedyczak
 */
public class JettyDefaultHandler extends AbstractHandler
{
	@Override
	public void handle(String target, Request baseRequest, HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException
	{
		if (response.isCommitted() || baseRequest.isHandled())
			return;

		baseRequest.setHandled(true);

		String method = request.getMethod();

		if (!method.equals(HttpMethod.GET.toString()) || !request.getRequestURI().equals("/"))
		{
			response.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}

		response.setStatus(HttpServletResponse.SC_NOT_FOUND);
		response.setContentType(MimeTypes.Type.TEXT_HTML.toString());

		ByteArrayISO8859Writer writer = new ByteArrayISO8859Writer(1500);

		writer.write("<HTML><HEAD><TITLE>Error 404: Requested page not found");
		writer.write("</TITLE><BODY><H1>Requested page not found</H1>");
		writer.write("</BODY></HTML>\n");
		writer.flush();
		response.setContentLength(writer.size());
		OutputStream out = response.getOutputStream();
		writer.writeTo(out);
		out.close();
		writer.close();
	}
}

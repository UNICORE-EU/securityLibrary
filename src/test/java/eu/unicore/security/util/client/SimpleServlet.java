/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 21-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import java.io.IOException;
import java.io.PrintStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SimpleServlet extends HttpServlet
{
	private static final long serialVersionUID = 1L;

	public static final String OK_GET = "OK-GET";
	public static final String OK_POST = "OK-POST";
	
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
		throws ServletException, IOException
	{
		write(OK_GET, resp);
	}
	
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) 
		throws ServletException, IOException
	{
		String timeoutS = req.getParameter("timeout");
		if (timeoutS != null)
		{
			int timeout = Integer.parseInt(timeoutS);
			try
			{
				Thread.sleep(timeout);
			} catch (InterruptedException e)
			{
			}
		}
		write(OK_POST, resp);
	}
	
	private void write(String what, HttpServletResponse resp) throws IOException
	{
		PrintStream out = new PrintStream(resp.getOutputStream());
		out.print(what);
		out.flush();
		resp.flushBuffer();
	}
}

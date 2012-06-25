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
	public static final String BIG_GET = "OK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GET" +
			"OK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GET" +
			"OK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GET" +
			"OK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GETOK-GET";
	
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
		throws ServletException, IOException
	{
		String bigResp = req.getParameter("gobig");
		if (bigResp == null)
			write(OK_GET, resp);
		else
			write(BIG_GET, resp);
	}
	
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) 
		throws ServletException, IOException
	{
		String timeoutS = req.getParameter("timeout");
		if (timeoutS != null)
		{
			int timeout = Integer.parseInt(timeoutS);
			System.out.println("Sleeping for " + timeout);
			try
			{
				Thread.sleep(timeout);
			} catch (InterruptedException e)
			{
			}
			System.out.println("Woke up!");
		}
		write(OK_POST, resp);
	}
	
	private void write(String what, HttpServletResponse resp) throws IOException
	{
		resp.setContentType("text/plain");
		resp.setContentLength(what.length());
		PrintStream out = new PrintStream(resp.getOutputStream());
		out.print(what);
		out.flush();
		resp.flushBuffer();
	}
}

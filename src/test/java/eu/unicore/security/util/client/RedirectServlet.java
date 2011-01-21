/*
 * Copyright (c) 2011 ICM Uniwersytet Warszawski All rights reserved.
 * See LICENCE file for licencing information.
 *
 * Created on 21-01-2011
 * Author: K. Benedyczak <golbi@mat.umk.pl>
 */
package eu.unicore.security.util.client;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class RedirectServlet extends HttpServlet
{
	private static final long serialVersionUID = 1L;
	private int nn = 0;
	
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) 
		throws ServletException, IOException
	{
		resp.sendRedirect(req.getParameter("redirect-to"));
	}
	
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) 
		throws ServletException, IOException
	{
		String num = req.getParameter("num");
		if (num != null && Integer.parseInt(num) > nn)
		{
			nn++;
			System.out.println("Sending " + nn + " redirect");
			resp.sendRedirect(req.getParameter("redirect-to-first"));
			return;
		}
		System.out.println("Sending final redirect");
		resp.sendRedirect(req.getParameter("redirect-to"));
	}
}

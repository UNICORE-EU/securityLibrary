package eu.unicore.security.util.jetty;

import org.apache.log4j.Level;
import org.mortbay.log.Logger;

import eu.unicore.security.util.Log;


/**
 * Route Jetty logging through log4j using a predefined {@link Log#CONNECTIONS} category. If
 * you want to change the category extend this class. The default constructor must
 * be always present.
 * 
 * @author schuller
 */
public class JettyLogger implements Logger {

	private final org.apache.log4j.Logger log;

	public JettyLogger() {
		log=getLog4jLogger();
	}
	
	/**
	 * Override this class to create a non-default logger.
	 * @return
	 */
	protected org.apache.log4j.Logger getLog4jLogger() {
		return Log.getLogger(Log.CONNECTIONS, JettyLogger.class);
	}
	
	public void debug(String msg, Throwable th) {
		log.debug(msg, th);
	}

	public void debug(String msg, Object arg0, Object arg1) {
		log.debug(msg);
	}

	public Logger getLogger(String name) {
		return this;
	}

	public void info(String msg, Object arg0, Object arg1) {
		log.info(format(msg, arg0, arg1));
	}

	public boolean isDebugEnabled() {
		return log.isDebugEnabled();
	}

	public void setDebugEnabled(boolean enabled) {
		log.setLevel(Level.DEBUG);
	}

	public void warn(String msg, Throwable th) {
		Log.logException(msg,th,log);
	}

	public void warn(String msg, Object arg0, Object arg1) {
		log.warn(format(msg,arg0,arg1));
	}

	//taken from Jetty StdErrLog class
	private String format(String msg, Object arg0, Object arg1) {
		int i0=msg.indexOf("{}");
		int i1=i0<0?-1:msg.indexOf("{}",i0+2);

		if (arg1!=null && i1>=0)
			msg=msg.substring(0,i1)+arg1+msg.substring(i1+2);
		if (arg0!=null && i0>=0)
			msg=msg.substring(0,i0)+arg0+msg.substring(i0+2);
		return msg;
	}
}

package eu.unicore.util;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import eu.unicore.util.configuration.PropertiesHelper;

public class Log {
	
	private static LoggerFactory spi;
	
	static {
		System.setProperty("java.util.logging.manager", "org.apache.logging.log4j.jul.LogManager");
		
		String factName = System.getProperty(LoggerFactory.LOGGER_FACTORY_PROPERTY);
		if (factName != null) {
			try
			{
				Class<?> factClazz = Class.forName(factName);
				Object factRaw = factClazz.getConstructor().newInstance();
				spi = (LoggerFactory) factRaw;
			} catch (Exception e)
			{
				e.printStackTrace();
				System.err.println("Can't instantiate logger factory class: " + factName + 
						" using default");
				spi = new DefaultLogFactory();
			}

		} else
			spi = new DefaultLogFactory();
	}

	protected Log(){}

	/**
	 * logger prefix for general UNICORE stuff
	 */
	public static final String UNICORE="unicore";

	/**
	 * logger prefix for admin stuff
	 */
	public static final String ADMIN=UNICORE+".admin";

	/**
	 * logger prefix for persistence related code
	 */
	public static final String PERSISTENCE=UNICORE+".persistence";

	/**
	 * logger prefix for services
	 */
	public static final String SERVICES=UNICORE+".services";

	/**
	 * logger prefix for security
	 */
	public static final String SECURITY=UNICORE+".security";

	/**
	 * logger prefix for client stack
	 */
	public static final String CLIENT=UNICORE+".client";

	/**
	 * logger prefix for connection logging
	 */
	public static final String CONNECTIONS=UNICORE+".connections";

	/**
	 * logger prefix for HTTP server logging
	 */
	public static final String HTTP_SERVER=UNICORE+".http.server";

	/**
	 * logger prefix for general logging of properties based configuration handling, used
	 * by {@link PropertiesHelper} extensions.
	 */
	public static final String CONFIGURATION=UNICORE+".configuration";

	/**
	 * returns a logger name, using the given prefix and the simple name
	 * of the given class
	 * 
	 * @param prefix - the prefix to use
	 * @param clazz - the class
	 * @return logger name
	 */
	public static String getLoggerName(String prefix, Class<?>clazz){
		return spi.getLoggerName(prefix, clazz);
	}

	/**
	 * returns a logger, using the given prefix and the simple name
	 * of the given class
	 * 
	 * @param prefix - the prefix to use
	 * @param clazz - the class
	 * @return logger
	 */
	public static Logger getLogger(String prefix, Class<?>clazz){
		return spi.getLogger(prefix, clazz);
	}

	/** 
	 * log an error message to the default logger ("unicore")
	 * A human-friendly message is constructed and logged at "INFO" level.
	 * The stack trace is logged at "DEBUG" level.
	 * 
	 * @param message - the error message
	 * @param cause - the cause of the error
	 *
	 */
	public static void logException(String message, Throwable cause){
		logException(message, cause, LogManager.getLogger(UNICORE));
	}

	// keep track of when message was last logged
	static final Map<Integer,Long>errorLogTimes = new ConcurrentHashMap<Integer, Long>();
	// keep track of how often a message was NOT logged
	static final Map<Integer,Long>errorCounters = new ConcurrentHashMap<Integer, Long>(); 

	/**
	 * log an error message to the specified logger.
	 * A human-friendly message is constructed and logged at "ERROR" level.
	 * The stack trace is logged at "DEBUG" level.
	 * 
	 * To avoid repeated, massive logging of the same error, a hash over the message is computed and stored
	 * together with a timestamp. If the "same" message occurs within a minute of the last, it will not 
	 * get logged.
	 * 
	 * @param message - the error message
	 * @param cause - the cause of the error
	 * @param logger - the logger to use
	 */
	public static boolean logException(String message, Throwable cause, Logger logger){
		boolean logged = false;
		Integer hash = (message!=null? message.hashCode():0)+
				31*(cause!=null && cause.getMessage()!=null? cause.getMessage().hashCode():0)+
				31*31*logger.getName().hashCode();

		// when was this message last logged?
		Long ts = errorLogTimes.get(hash);
		// get number of suppressed log entries
		Long dropped = errorCounters.get(hash);
		if(dropped==null)dropped = 0l;

		if(errorLogTimes.size()>=500){
			Iterator<Map.Entry<Integer, Long>>iter = errorLogTimes.entrySet().iterator();
			while(iter.hasNext()){
				Map.Entry<Integer, Long> e = iter.next();
				if(System.currentTimeMillis()-60000 > e.getValue()){
					iter.remove();
					errorCounters.remove(e.getKey());
				}
			}
		}

		if(ts == null || System.currentTimeMillis()-60000>ts){
			if(dropped>0)message = "(repeated "+dropped+" times) "+message;
			logger.error(message);
			logged = true;
			if(errorLogTimes.size()<500){
				errorLogTimes.put(hash, System.currentTimeMillis());
				errorCounters.remove(hash);
			}
			if(cause!=null){
				logger.error("The root error was: "+getDetailMessage(cause));
				if(logger.isDebugEnabled())logger.debug("Stack trace",cause);
				else{
					logger.error("To see the full error stack trace, set log4j.logger."+logger.getName()+"=DEBUG");
				}
			}
		}
		else{
			if(errorCounters.size()<500){
				errorCounters.put(hash, Long.valueOf(dropped+1));
			}
		}
		return logged;
	}

	/**
	 * construct a (hopefully) useful error message from the root cause of an 
	 * exception
	 * 
	 * @param throwable - the exception
	 * @return detailed error message
	 */
	public static String getDetailMessage(Throwable throwable){
		StringBuilder sb=new StringBuilder();
		Throwable cause=throwable;
		String message=null;
		String type="";
		while(cause!=null){
			type=cause.getClass().getName();
			message=cause.getMessage();
			cause=cause.getCause();
		}
		if(message!=null)sb.append(type).append(": ").append(message);
		else sb.append(type).append(" (no further message available)");
		return sb.toString();
	}

	/**
	 * construct a user-friendly error message 
	 * 
	 * @param message
	 * @param cause
	 */
	public static String createFaultMessage(String message, Throwable cause){
		return message+": "+getDetailMessage(cause);
	}

}

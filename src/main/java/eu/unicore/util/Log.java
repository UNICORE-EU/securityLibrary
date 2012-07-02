package eu.unicore.util;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;

public class Log {
	private static LoggerFactory spi;
	static {
		String factName = System.getProperty(LoggerFactory.LOGGER_FACTORY_PROPERTY);
		if (factName != null) {
			try
			{
				Class<?> factClazz = Class.forName(factName);
				Object factRaw = factClazz.newInstance();
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
	 * logger prefix for general WSRFlite code
	 */
	public static final String WSRFLITE=UNICORE+".wsrflite";

	/**
	 * logger prefix for persistence related code
	 */
	public static final String PERSISTENCE=UNICORE+".wsrflite.persistence";
	
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
	public static final String HTTP_SERVER=UNICORE+".httpserver";

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
	 * log an error message to the default logger ("unicore.wsrflite")
	 * A human-friendly message is constructed and logged at "INFO" level.
	 * The stack trace is logged at "DEBUG" level.
	 * 
	 * @param message - the error message
	 * @param cause - the cause of the error
	 *
	 */
	public static void logException(String message, Throwable cause){
		logException(message,cause,Logger.getLogger(WSRFLITE));
	}
	
	/**
	 * log an error message to the specified logger.
	 * A human-friendly message is constructed and logged at "ERROR" level.
	 * The stack trace is logged at "DEBUG" level.
	 * 
	 * @param message - the error message
	 * @param cause - the cause of the error
	 * @param logger - the logger to use
	 */
	public static void logException(String message, Throwable cause, Logger logger){
		logger.error(message);
		if(cause!=null){
			logger.error("The root error was: "+getDetailMessage(cause));
			if(logger.isDebugEnabled())logger.debug("Stack trace",cause);
			else{
				logger.error("To see the full error stack trace, set log4j.logger."+logger.getName()+"=DEBUG");
			}
		}
	}
	
	/**
	 * construct a (hopefully) useful error message from the root cause of an 
	 * exception
	 * 
	 * @param throwable - the exception
	 * @return datailed error message
	 */
	public static String getDetailMessage(Throwable throwable){
		StringBuilder sb=new StringBuilder();
		Throwable cause=throwable;
		String message=null;
		String type=null;type=cause.getClass().getName();
		do{
			type=cause.getClass().getName();
			message=cause.getMessage();
			cause=cause.getCause();
		}
		while(cause!=null);
		
		if(message!=null)sb.append(type).append(": ").append(message);
		else sb.append(type).append(" (no further message available)");
		return sb.toString();
	}
	
	/**
	 * construct a user-friendly error message 
	 * 
	 * @param message
	 * @param cause
	 * @return
	 */
	public static String createFaultMessage(String message, Throwable cause){
		return message+": "+getDetailMessage(cause);
	}
	
	public static void cleanLogContext(){
		MDC.remove("clientName");
	}
}

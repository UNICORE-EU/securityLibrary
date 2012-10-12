package eu.unicore.util;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation that enables concurrent access to Resources on a web method level.</br>
 * Thus, read-only methods like GetResourceProperty() can be executed concurrently, 
 * while for others such as SetResourceProperty() the Resource will be locked</br>
 * 
 * @author schuller
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface ConcurrentAccess {

	/**
	 * this flag controls whether concurrent access is allowed. 
	 * It defaults to <code>false</code>
	 */
	public boolean allow() default false;
}

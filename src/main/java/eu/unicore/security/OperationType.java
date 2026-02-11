package eu.unicore.security;

/**
 * Predefined operation types. This enum can be freely extended in future - PDP should adapt itself automatically.
 * @author K. Benedyczak
 */
public enum OperationType {
	
	/**
	 * The operation is read-only, i.e. it doesn't modify a resource state.
	 */
	read,
	
	/**
	 * The operation is a write operation, but does not require ownership of the resource.
	 */
	write,
	
	/**
	 * The operation can modify the resource and we can assume that operations of this type 
	 * require the full access to the resource.
	 */
	modify,
	
}

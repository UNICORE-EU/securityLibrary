package eu.unicore.util.httpclient;

public interface SessionIDProviderFactory {
	
	public SessionIDProvider get(String URI);

}

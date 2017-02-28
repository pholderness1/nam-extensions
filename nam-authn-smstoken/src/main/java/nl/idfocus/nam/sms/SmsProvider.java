package nl.idfocus.nam.sms;

public interface SmsProvider 
{
	/**
	 * Initialize the provider by passing the NAM module configuration into it. 
	 * Allows for a debug parameter which should control verbose logging.
	 * @param config
	 * @param dbg
	 */
	void init( SmsConfig config, boolean dbg );

	/**
	 * Send the actual text message to a given number. 
	 * @param message
	 * @param number
	 * @param timeout
	 * @return
	 */
	boolean send( String message, String number, int timeout );

	/**
	 * Indication whether or not the provider is correctly initialized and ready to send. 
	 * @return
	 */
	boolean ready();

	/**
	 * Obligatory method to return the provider descriptive name. Used for identification in module logging.
	 * @return
	 */
	String getName();

	/**
	 * Return a list of supported and required parameters that this SMS provider needs. 
	 * The module will try to fulfill these parameters in the configuration, and throw an error if mandatory parameters are missing. 
	 * @return
	 */
	SmsParameterDesc[] getParameters();

	/**
	 * Indication whether or not this module needs the actual Principal object of the user logging in. 
	 * If this is the case, the module calls the {@link #update(SmsConfig)} method to pass the configuration updated with the Principal information. 
	 * @return
	 */
	boolean needPrincipal();

	void update( SmsConfig config );
	
}

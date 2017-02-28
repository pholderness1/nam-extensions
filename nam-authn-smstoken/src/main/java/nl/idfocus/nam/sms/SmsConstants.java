package nl.idfocus.nam.sms;

/**
 * A set of constants that is being used to pass information on to the displayed JSP page 
 * and to save data in the session object.
 * @author mvreijn
 *
 */
public class SmsConstants 
{
	public static final String ATTR_NUMBER 		= "number";
	public static final String ATTR_NUMBER_ALT 	= "altnumber";
	public static final String ATTR_ERROR 		= "error";
	public static final String ATTR_TOKEN 		= "token";
	public static final String ATTR_DELAY 		= "delay";

	/** Error message string indicating an incorrect token was received */
	public static final String ERR_CODE_INVALID = "smsToken.code.wrong";
	/** Error message string indicating the user has no phone numbers listed */
	public static final String ERR_NO_NUMBER    = "smsToken.number.missing";
	/** Error message string indicating the sending of the SMS message failed */
	public static final String ERR_SEND_FAILED  = "smsToken.send.failed";

	private SmsConstants() {}
}

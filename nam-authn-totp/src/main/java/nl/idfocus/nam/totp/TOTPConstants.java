package nl.idfocus.nam.totp;

import java.util.Properties;

public class TOTPConstants 
{
	public final static String PARAM_WINDOW_SIZE  = "windowSize";
	public final static String PARAM_KEY_SIZE     = "keySize";
	public final static String PARAM_SCRATCH      = "scratchCodes";
	public final static String PARAM_SCRATCH_SIZE = "scratchCodeSize";
	public final static String PARAM_STORE_TYPE   = "storeType";
	public static final String PARAM_IMAGE_SIZE   = "imageSize";

	public final static String PARAM_INPUT_TOKEN    = "inputToken";
	public final static String PARAM_INPUT_BACKUP   = "inputScratchcode";
	public final static String PARAM_INPUT_REGISTER = "inputRegister";
	public final static String PARAM_INPUT_JSP_REG  = "JSP_REG";
	public final static String PARAM_INPUT_JSP_AUT  = "JSP_AUT";
	public final static String PARAM_INPUT_POSTPONE = "inputPostpone";
	public final static String PARAM_ISSUER_NAME    = "issuerName";
	public final static String PARAM_USER_NAME      = "useUserName";
	public final static String PARAM_USER_NAME_ATTR = "userNameAttribute";
	public final static String PARAM_REENROLL_ATTR  = "reEnrollmentAttribute";
	public final static String PARAM_EXP_COOKIE     = "expirationCookie";
	public final static String PARAM_EXP_ATTRIBUTE  = "expirationAttribute";
	public final static String PARAM_EXP_TIME       = "expirationTime";

	public static final String STORE_EDIR = "eDirectory";
	public static final String STORE_NIDP = "NIDP";
	public static final String STORE_LDAP = "LDAP";
	public static final String STORE_PWM  = "PWM";

	public static final String JSP_ATTR_IMAGE   = "totp-qrimage";
	public static final String JSP_ATTR_SECRET  = "totp-secret";
	public static final String JSP_ATTR_USER    = "totp-username";
	public static final String JSP_ATTR_DELAY   = "totp-delay";
	public static final String JSP_ATTR_ERROR   = "totp-error";

	public static final String SESSION_ATTR_REG   = "totp-registration";
	public static final String SESSION_ATTR_DELAY = "totp-delay";

	public static final String ERR_CODE_INVALID = "totp.code.invalid";
	
	public static Properties getDefaults()
	{
		Properties props = new Properties();
		props.setProperty(PARAM_KEY_SIZE,    "10");
		props.setProperty(PARAM_SCRATCH,      "5");
		props.setProperty(PARAM_SCRATCH_SIZE, "8");
		props.setProperty(PARAM_WINDOW_SIZE,  "3");
		props.setProperty(PARAM_IMAGE_SIZE, "200");
		props.setProperty(PARAM_STORE_TYPE,   STORE_NIDP );
		return props;
	}
}

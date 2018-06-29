package nl.idfocus.nam.totp;

import java.util.Properties;

public class TOTPConstants 
{
	public static final String PARAM_WINDOW_SIZE  = "windowSize";
	public static final String PARAM_KEY_SIZE     = "keySize";
	public static final String PARAM_SCRATCH      = "scratchCodes";
	public static final String PARAM_SCRATCH_SIZE = "scratchCodeSize";
	public static final String PARAM_STORE_TYPE   = "storeType";
    public static final String PARAM_IMAGE_SIZE   = "imageSize";
    public static final String PARAM_PBE_KEY      = "pbeKey";

	public static final String PARAM_INPUT_TOKEN    = "inputToken";
	public static final String PARAM_INPUT_BACKUP   = "inputScratchcode";
	public static final String PARAM_INPUT_REGISTER = "inputRegister";
	public static final String PARAM_INPUT_JSP_REG  = "JSP_REG";
	public static final String PARAM_INPUT_JSP_AUT  = "JSP_AUT";
	public static final String PARAM_INPUT_POSTPONE = "inputPostpone";
	public static final String PARAM_ISSUER_NAME    = "issuerName";
	public static final String PARAM_USER_NAME      = "useUserName";
	public static final String PARAM_USER_NAME_ATTR = "userNameAttribute";
	public static final String PARAM_REENROLL_ATTR  = "reEnrollmentAttribute";
	public static final String PARAM_EXP_COOKIE     = "expirationCookie";
	public static final String PARAM_EXP_ATTRIBUTE  = "expirationAttribute";
	public static final String PARAM_EXP_TIME       = "expirationTime";

	public static final String STORE_EDIR = "EDIR";
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

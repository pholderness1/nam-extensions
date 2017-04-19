package nl.idfocus.nam.authentication;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.Properties;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.servlet.http.Cookie;

import nl.idfocus.nam.totp.Authenticator;
import nl.idfocus.nam.totp.TOTPConstants;
import nl.idfocus.nam.totp.TOTPException;
import nl.idfocus.nam.totp.UserRegistration;
import nl.idfocus.nam.util.LogFormatter;
import nl.idfocus.nam.util.Sha256;

import com.novell.nidp.NIDPConstants;
import com.novell.nidp.NIDPException;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.NIDPSubject;
import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.authentication.local.PageToShow;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.authority.ldap.LDAPPrincipal;

/**
 * Custom Authentication class for NetIQ Access Manager<br/>
 * <p>
 * The TOTPAuth class performs Time-based OTP authentication similar to Google Authenticator. <br/>
 * </p><p>
 * The settings of this class allow for extensive configuration regarding displayed information, TOTP settings, enrollment and re-enrollment. <br/>
 * Features include storage of the shared secret in NIDP Secret (default), eDirectory Secret Store, PWM PAM Format or encrypted LDAP attribute. <br/>
 * AES encryption is used for secure storage. <br/>
 * </p>
 * @author IDFocus B.V. (mvreijn@idfocus.nl)
 * @version Tested on NetIQ Access Manager 4.x
 */
public class TOTPAuth extends LocalAuthenticationClass 
{

	private static final Logger logger   = LogFormatter.getConsoleLogger( TOTPAuth.class.getName() );
	private static final Level  loglevel = Level.INFO;
	private static final Level  dbglevel = Level.FINE;
	private static final Level  errlevel = Level.SEVERE;

	/**
	 * By setting this property name on the class or method, the debug mode may be enabled. 
	 * This overrides the default specified in {@link #DEF_DEBUG}
	 */
	private static final String PROP_DEBUG   = "DEBUG";
	/**
	 * By setting this property name on the class or method, the name of the token <br/>
	 * input field may be altered from the default specified in {@link #DEF_INPUT_TOKEN}
	 */
	private static final String PROP_INPUT_TOKEN    = TOTPConstants.PARAM_INPUT_TOKEN;
	/**
	 * By setting this property name on the class or method, the name of the backupcode <br/>
	 * input field may be altered from the default specified in {@link #DEF_INPUT_BACKUP}	 * 
	 */
	private static final String PROP_INPUT_BACKUP    = TOTPConstants.PARAM_INPUT_BACKUP;
	/**
	 * By setting this property name on the class or method, the name of the totp <br/>
	 * registration JSP page may be altered from the default specified in {@link #DEF_INPUT_JSP_REG}
	 */
	private static final String PROP_INPUT_JSP_REG  = TOTPConstants.PARAM_INPUT_JSP_REG;
	/**
	 * By setting this property name on the class or method, the name of the totp <br/>
	 * authentication JSP page may be altered from the default specified in {@link #DEF_INPUT_JSP_AUT}
	 */
	private static final String PROP_INPUT_JSP_AUT  = TOTPConstants.PARAM_INPUT_JSP_AUT;
	/**
	 * By setting this property name on the class or method, the name of the 'postpone' <br/>
	 * input field may be altered from the default specified in {@link #DEF_INPUT_POSTPONE}
	 */
	private static final String PROP_INPUT_POSTPONE = TOTPConstants.PARAM_INPUT_POSTPONE;
	/**
	 * By setting this property name on the class or method, the name of the issueing organization <br/>
	 * that is displayed in a user's authenticator window is set. The default is specified in {@link #DEF_ISSUER_NAME}
	 */
	private static final String PROP_ISSUER_NAME    = TOTPConstants.PARAM_ISSUER_NAME;
	/**
	 * By setting this property name on the class or method to 'true', the username <br/>
	 * is displayed in a user's authenticator window as the credential. <br/>
	 * When set to 'false', the attribute specified in {@link #DEF_USER_NAME_ATTR} is read and the first value is used. <br/>
	 * The default setting is specified in {@link #DEF_USER_NAME}
	 */
	private static final String PROP_USER_NAME      = TOTPConstants.PARAM_USER_NAME;
	/**
	 * When {@link #PARAM_USER_NAME} is set to 'false', this value is used for the attribute name which is read <br/>
	 * from the user object to display in a user's authenticator window as the credential. <br/>
	 * The default setting is specified in {@link #DEF_USER_NAME_ATTR}
	 */
	private static final String PROP_USER_NAME_ATTR = TOTPConstants.PARAM_USER_NAME_ATTR;
	/**
	 * By setting this property name on the class or method to a valid attribute name, the boolean value of that attribute <br/>
	 * is used to determine if a user needs to re-enroll their TOTP secret key using a QR code. <br/>
	 * This setting overrides any current registration and also clears "do not ask me again" cookies. <br/>
	 * The default setting is specified in {@link #DEF_REENROLL_ATTR} (and is empty, disabling this functionality).
	 */
	private static final String PROP_REENROLL_ATTR  = TOTPConstants.PARAM_REENROLL_ATTR;
	/**
	 * By setting this property name on the class or method, the name prefix is determined that is used for the <br/>
	 * "do not ask me again" cookie. <br/>
	 * By overriding this value, it is possible to use the same cookie for both TOTP and SmsToken authentication classes.<br/>
	 * The default setting is specified in {@link #DEF_EXP_COOKIE}
	 */
	private static final String PROP_EXP_COOKIE     = TOTPConstants.PARAM_EXP_COOKIE;
	/**
	 * By setting this property name on the class or method, the attribute is determined that is used for the <br/>
	 * delay value of the "do not ask me again" cookie. <br/>
	 * The attribute must contain a numeric string, and overrides the default delay on a per-user basis.<br/>
	 * The default setting is specified in {@link #DEF_EXP_ATTRIBUTE}
	 */
	private static final String PROP_EXP_ATTRIBUTE  = TOTPConstants.PARAM_EXP_ATTRIBUTE;
	/**
	 * By setting this property name on the class or method, the default delay is determined that is used for the <br/>
	 * "do not ask me again" cookie. <br/>
	 * By setting this value to a number greater than 0, the number of days is set that the user may postpone re-entering their token.<br/>
	 * The default setting is specified in {@link #DEF_EXP_TIME} (and in 0, disabling delay).
	 */
	private static final String PROP_EXP_TIME       = TOTPConstants.PARAM_EXP_TIME;

	private static final String DEF_DEBUG          = "false";
	private static final String DEF_INPUT_TOKEN    = "Ecom_Token";
	private static final String DEF_INPUT_BACKUP   = "Ecom_Backupcode";
	private static final String DEF_INPUT_JSP_REG  = "totpregistration";
	private static final String DEF_INPUT_JSP_AUT  = "totptoken";
	private static final String DEF_INPUT_POSTPONE = "Ecom_Postpone";
	private static final String DEF_ISSUER_NAME    = "NetIQ Access Manager";
	private static final String DEF_USER_NAME      = "true";
	private static final String DEF_USER_NAME_ATTR = "cn";
	private static final String DEF_REENROLL_ATTR  = "";
	private static final String DEF_EXP_COOKIE     = "idftotpauth";
	private static final String DEF_EXP_ATTRIBUTE  = "description";
	private static final String DEF_EXP_TIME       = "0";

	private final String valueInputToken;
	private final String valueInputScratchcode;
	private final String inputJspRegistration;
	private final String inputJspAuthentication;
	private final String valueInputPostpone;
	private final String issuerName;
	private final boolean useUserName;
	private final String userNameAttribute;
	private final String reEnrollmentAttribute;
	private final String expirationCookieName;
	private final String expirationAttributeName;
	private final int    expirationTime;

	private static final String PKGBUILD = TOTPAuth.class.getPackage().getImplementationVersion();
	private NIDPPrincipal localPrincipal;
	private final String sessionUser;
	private final boolean debugMode;

	public TOTPAuth(Properties props, ArrayList<UserAuthority> stores) 
	{
		super(props, stores);
		logger.log(loglevel, "TOTP Token Authentication Class build {0} (c) IDFocus B.V. <info@idfocus.nl>", PKGBUILD);
		// Determine debug setting
		debugMode = Boolean.parseBoolean( props.getProperty( PROP_DEBUG, DEF_DEBUG ) );
		if ( debugMode )
		{
			LogFormatter.setLoggerDebugMode(logger);
			// Read setup properties DEBUG
			Iterator<?> itr = props.keySet().iterator();
			while ( itr.hasNext() )
			{
				String key = (String) itr.next();
				logger.log( dbglevel, "[DBG] property {0}: {1}", new Object[] { key, props.getProperty(key) });
			}
		}
		/* 
		 * read property settings
		 */
		valueInputToken    = props.getProperty( PROP_INPUT_TOKEN   , DEF_INPUT_TOKEN );
		valueInputScratchcode = props.getProperty( PROP_INPUT_BACKUP, DEF_INPUT_BACKUP );
		valueInputPostpone = props.getProperty( PROP_INPUT_POSTPONE, DEF_INPUT_POSTPONE );
		inputJspRegistration  = props.getProperty( PROP_INPUT_JSP_REG , DEF_INPUT_JSP_REG );
		inputJspAuthentication  = props.getProperty( PROP_INPUT_JSP_AUT , DEF_INPUT_JSP_AUT );
		issuerName    = props.getProperty( PROP_ISSUER_NAME   , DEF_ISSUER_NAME );
		userNameAttribute = props.getProperty( PROP_USER_NAME_ATTR, DEF_USER_NAME_ATTR );
		reEnrollmentAttribute  = props.getProperty( PROP_REENROLL_ATTR , DEF_REENROLL_ATTR );
		expirationCookieName     = props.getProperty( PROP_EXP_COOKIE    , DEF_EXP_COOKIE );
		expirationAttributeName  = props.getProperty( PROP_EXP_ATTRIBUTE , DEF_EXP_ATTRIBUTE );
		// Boolean value is parsed
		useUserName      = Boolean.parseBoolean( props.getProperty( PROP_USER_NAME, DEF_USER_NAME ) );
		// Integer value is parsed
		expirationTime       = getIntValue( PROP_EXP_TIME, props.getProperty( PROP_EXP_TIME, DEF_EXP_TIME ) );
		sessionUser = getProperty("findSessionUser");
		logger.log( loglevel, "Done." );
	}

	@Override
	public String getType() 
	{
		return AuthnConstants.TOKEN;
	}

	@Override
	protected int doAuthenticate() 
	{
		localPrincipal = resolveUserPrincipal();
		if ( localPrincipal == null )
		{
			logger.log( Level.WARNING, "Could not resolve Principal, failing login (is this the first method in a contract?)" );
			return NOT_AUTHENTICATED;
		}
		logger.log( loglevel, "Logging in: "+localPrincipal.getUserIdentifier() );
		Properties props = createPropertySet();
		// Load up authenticator
		Authenticator authn;
		try
		{
			authn = new Authenticator( props, localPrincipal );
		}
		catch (TOTPException e)
		{
			logger.log( errlevel, "Could not initialize TOTP Authenticator!", e );
			return NOT_AUTHENTICATED;
		}
		/*
		 * ********************** Start first flow ********************** 
		 */
		if ( isFirstCallAfterPrevMethod() )
		{
			boolean registered = hasUserRegistration(authn, reEnrollmentAttribute, false);
			int delay = getDelayUntilNextAuth( localPrincipal );
			// If delay > 0 and cookie is present and valid, return
			String cookieName = getCookieName( expirationCookieName, localPrincipal.getUserIdentifier() );
			if ( registered && delay > 0 && checkCookieValidity( cookieName ) )
			{
				logger.log(loglevel, "Cookie {0} is present and valid, skipping authentication", cookieName);
				setPrincipal(localPrincipal);
				return AUTHENTICATED;
			}
			else
			{
				logger.log(dbglevel, "Cookie {0} is not present or not valid, clearing", cookieName);
				clearCookie( cookieName );
			}
			String userName = resolveUserName();
			if ( registered )
			{
				logger.log(dbglevel, "Preparing token entry page.");
				prepareAuthenticationPage(userName, delay);
			}
			else
			{
				logger.log(dbglevel, "Preparing registration page.");
				prepareRegistrationPage(userName, props);
			}
			logger.log(dbglevel, "Show JSP file.");
			return SHOW_JSP;
		}
		/* 
		 * ********************** Start second flow ********************** 
		 */
		else if ( hasUserRegistration( authn, reEnrollmentAttribute, true ) )
		{
			logger.log(dbglevel, "Process authentication.");
			String token = m_Request.getParameter( valueInputToken );
			String scratchcode = m_Request.getParameter( valueInputScratchcode );
			Integer delay = (Integer) m_Request.getSession().getAttribute( TOTPConstants.SESSION_ATTR_DELAY );
			if ( delay == null )
				delay = expirationTime;
			if (authn.checkCode(token, System.currentTimeMillis()))
			{
				logger.log(dbglevel, "Authentication successful.");
				addDelayCookieIfNeeded( delay );
				setPrincipal(localPrincipal);
				return AUTHENTICATED;
			}
			else if (isValidScratchCode(authn, scratchcode))
			{
				// Save rest of codes
				try
				{
					authn.persist();
				}
				catch (TOTPException e)
				{
					logger.log(errlevel, "Could not delete scratch code. Failing authentication.", e);
					return NOT_AUTHENTICATED;
				}
				// Can't use cookie with scratch code
				setPrincipal(localPrincipal);
				logger.log(dbglevel, "Authentication successful using {0} as a scratch code.", scratchcode);
				return AUTHENTICATED;
			}
			else
			{
				logger.log(dbglevel, "Authentication failed. Returning page.");
				String userName = resolveUserName();
				prepareAuthenticationPage(userName, delay);
				m_PageToShow.addAttribute( TOTPConstants.JSP_ATTR_ERROR, TOTPConstants.ERR_CODE_INVALID );
				return SHOW_JSP;
			}
		}
		/* 
		 * ********************** Start third flow ********************** 
		 */
		else
		{
			logger.log(dbglevel, "Process registration.");
			String token = m_Request.getParameter( valueInputToken );
			UserRegistration reg = (UserRegistration)m_Request.getSession().getAttribute( TOTPConstants.SESSION_ATTR_REG );
			try
			{
				authn.setRegistration( reg );
				if(authn.checkCode(token, System.currentTimeMillis()))
				{
					logger.log(dbglevel, "Authentication successful.");
					authn.persist();
					logger.log(dbglevel, "Registration saved.");
					setPrincipal(localPrincipal);
					return AUTHENTICATED;
				}
			}
			catch (TOTPException e)
			{
				logger.log( errlevel, "error saving key: "+e.getMessage(), e );
			}
		}
		logger.log(dbglevel, "Returning NOT_AUTHENTICATED.");
		return NOT_AUTHENTICATED;
	}

	private boolean isValidScratchCode(Authenticator authn, String token)
	{
		if (token != null && token.matches("\\d+"))
		{
			try
			{
				return authn.validateScratchCode(Integer.parseInt(token));
			}
			catch (NumberFormatException | TOTPException e)
			{
				logger.log(Level.WARNING, "Could not validate scratch code "+token, e);
			}
		}
		return false;
	}

	private Properties createPropertySet()
	{
		Properties props = new Properties();
		props.putAll( TOTPConstants.getDefaults() );
		props.putAll( m_Properties );
		return props;
	}

	private String resolveUserName()
	{
		String userName = "";
		if ( useUserName )
		{
			userName = ((LDAPPrincipal)this.localPrincipal).getUserName();
		}
		else
		{
			Attribute userNameAttr = getAttributeFromPrincipal( localPrincipal, userNameAttribute );
			try {
				userName = (String)userNameAttr.get();
			} catch (NamingException e) {}
		}
		// Fallback is principal DN
		if ( userName == null || userName.isEmpty() )
			userName = localPrincipal.getUserIdentifier();
		logger.log(dbglevel, "Resolved username '{0}'", userName);
		return userName;
	}

	private void prepareAuthenticationPage(String userName, int delay)
	{
		m_PageToShow = new PageToShow( inputJspAuthentication );
		m_PageToShow.addAttribute( TOTPConstants.JSP_ATTR_USER, userName );
		m_PageToShow.addAttribute( NIDPConstants.ATTR_URL, ( getReturnURL() != null ? getReturnURL() : m_Request.getRequestURL().toString() ) );
		if ( delay > 0 )
		{
			logger.log(dbglevel, "Adding delay {0}.", delay);
			m_Request.getSession().setAttribute( TOTPConstants.SESSION_ATTR_DELAY, delay );
			m_PageToShow.addAttribute( TOTPConstants.JSP_ATTR_DELAY, Integer.toString( delay ) );
		}		
	}

	private void prepareRegistrationPage(String userName, Properties props)
	{
		UserRegistration reg = new UserRegistration( props );
		reg.setUserName(userName);
		reg.setOrgName( issuerName );
		m_PageToShow = new PageToShow( inputJspRegistration );
		m_PageToShow.addAttribute( NIDPConstants.ATTR_URL, ( getReturnURL() != null ? getReturnURL() : m_Request.getRequestURL().toString() ) );
		try
		{
			String image = reg.getQRImageString();
			logger.log(dbglevel, "Created QR image.");
			m_PageToShow.addAttribute( TOTPConstants.JSP_ATTR_IMAGE, image );
			m_PageToShow.addAttribute( TOTPConstants.JSP_ATTR_SECRET, reg.getSecretKey() );
			m_Request.getSession().setAttribute( TOTPConstants.SESSION_ATTR_REG, reg );
		} catch (TOTPException e) {
			// TODO handle error status?
			logger.log(errlevel, "Error creating QR image: "+e.getMessage()+".");
			m_PageToShow.addAttribute( TOTPConstants.JSP_ATTR_ERROR, e.getMessage() );
		}		
	}

	private void addDelayCookieIfNeeded(int delay)
	{
		logger.log( dbglevel, "Checking cookie setting: "+m_Request.getParameter( valueInputPostpone ) );
		// Check delay option input
		if ( "on".equalsIgnoreCase( m_Request.getParameter( valueInputPostpone ) ) && delay > 0 )
		{
			// Prepare cookie and add to response
			String userid = localPrincipal.getUserIdentifier();
			logger.log( dbglevel, String.format( "Setting cookie with prefix %s and delay %s for user %s.", expirationCookieName, delay, userid ) );
			Cookie ck = createCookie( expirationCookieName, userid, delay );
			logger.log( dbglevel, "Setting cookie: "+ck.getName() );
			m_Response.addCookie(ck);
		}		
	}

	/**
	 * Resolve the current NIDP principal object by any known means.
	 * @return principal object for the current user
	 */
    private NIDPPrincipal resolveUserPrincipal()
    {
    	logger.log( dbglevel, "getting principal from localauthentication class");
        NIDPPrincipal nidpprincipal = getPrincipal();
        if ( nidpprincipal == null )
        {
	        logger.log( dbglevel, "getting principal from properties (contract)");
	        nidpprincipal = (NIDPPrincipal) m_Properties.get("Principal");
	        if ( nidpprincipal == null )
	        {
	        	logger.log( dbglevel, "getting subject from session");
	            if(sessionUser != null)
	            {
	                if( m_Session.isAuthenticated() )
	                {
	                    NIDPSubject nidpsubject = m_Session.getSubject();
	                    NIDPPrincipal[] allNidpPrincipals = nidpsubject.getPrincipals();
	                    logger.log( dbglevel, "found {0} principal(s) in session subject", allNidpPrincipals.length);
	                    if(allNidpPrincipals.length == 1)
	                    {
	                        nidpprincipal = allNidpPrincipals[0];
	                        logger.log( loglevel,  ( new StringBuilder() ).append("principal retrieved from authenticated session: ").append( nidpprincipal.getUserIdentifier() ).toString() );
	                    }
	                }
	                if(nidpprincipal == null)
	                	logger.log( dbglevel, "no single principal in session");
	            }
	        }
	        else
	        {
	        	logger.log( loglevel, (new StringBuilder()).append("retrieved principal from properties: ").append(nidpprincipal.getUserIdentifier()).toString());
	        }
        }
        else
        {
        	logger.log( loglevel, (new StringBuilder()).append("retrieved principal from localauthentication class: ").append(nidpprincipal.getUserIdentifier()).toString());
        }
        return nidpprincipal;
    }

	/**
	 * Check if the given date String in yyyyMMddHHmmssZ format is in the past.
	 * @param dateStr Date as a String in yyyyMMddHHmmssZ format
	 * @return true for in the past, false for in the future.
	 */
	private boolean isDatePast( String dateStr )
	{
		SimpleDateFormat format = new SimpleDateFormat( "yyyyMMddHHmmss'Z'" );
		Calendar cal = Calendar.getInstance();
		cal.setTimeZone( TimeZone.getTimeZone( "UTC" ) );
		Date today = cal.getTime();
		try {
			Date check = format.parse( dateStr );
			return today.after( check );
		} catch (ParseException e) {
			logger.log( loglevel, "Date parsing exception: "+e.getMessage()+" for value "+dateStr+" at position "+e.getErrorOffset() );
		} catch (NullPointerException e) {
			logger.log( loglevel, "Date parsing exception: "+e.getMessage()+" for value "+dateStr );
		}
		return false;
	}

	private int getDelayUntilNextAuth( NIDPPrincipal princ ) 
	{
		try {
			Attribute attr = getAttributeFromPrincipal( princ, expirationAttributeName );
			if ( attr.size() > 0 )
			{
				logger.log( dbglevel, attr.size()+" value"+(attr.size()>1?"s":"")+" found"+(attr.size()>1?", returning first one":""));
				Object value = attr.get();
				if ( value != null && value instanceof String )
				{
					logger.log( dbglevel, "parsing value");
					return getIntValue( PROP_EXP_ATTRIBUTE, (String)value );
				}
			}
			else
			{
				logger.log( loglevel, "no values found");
			}
		} catch (NamingException e) {
			logger.log( dbglevel,  "NamingException getting delay: "+e.getExplanation() );
		}
		return expirationTime;
	}

	private Cookie createCookie( String name, String uid, int delay ) 
	{
		String cname = getCookieName( name, uid );
		String contents = getExpirationDate(delay);
		Cookie result = new Cookie( cname, contents );
		result.setMaxAge( getSecondsUntilDelay(delay) );
		result.setSecure(true);
		logger.log( dbglevel, "Created cookie "+result.getName()+" with age "+result.getMaxAge()+" and value "+result.getValue() );
		return result;
	}

	private String getCookieName( String prefix, String userid )
	{
		try
		{
			String uid = Sha256.toHashString(userid);
			return prefix+uid;
		} catch (Exception e) {
			logger.log( errlevel, "Cannot generate unique cookie name: "+e.getMessage() );
		}
		return prefix;
	}

	/**
	 * Get the number of seconds until midnight as an integer value for use in cookies. 
	 * @return int representing the number of seconds until midnight
	 */
	private int getSecondsUntilDelay( int delay )
	{
		Calendar c = Calendar.getInstance();
        Date now = new Date();
        c.add(Calendar.DATE, delay );
        c.set(Calendar.HOUR_OF_DAY, 0);
        c.set(Calendar.MINUTE, 0);
        c.set(Calendar.SECOND, 0);
        c.set(Calendar.MILLISECOND, 0);
        Long howMany = ( c.getTimeInMillis()-now.getTime() ) / 1000 ;
        return howMany.intValue();
	}

	/**
	 * Get the date that the current authentication delay will expire. Uses UTC.
	 * @return Date as a String in yyyyMMddHHmmssZ format.
	 */
	private String getExpirationDate( int delay )
	{
		Calendar cal = Calendar.getInstance();
		cal.setTimeZone( TimeZone.getTimeZone( "UTC" ) );
		cal.set( Calendar.HOUR_OF_DAY , 23 );
		cal.set( Calendar.MINUTE , 59 );
		cal.set( Calendar.SECOND , 59 );
		cal.add( Calendar.DATE, delay );
		SimpleDateFormat format = new SimpleDateFormat( "yyyyMMddHHmmss'Z'" );
		return format.format( cal.getTime() );
	}

    private int getIntValue( String property, String value )
    {
    	try
    	{
    		return Integer.parseInt(value);
    	} catch (NumberFormatException e) {
    		logger.log(errlevel, "Could not determine numeric value for '"+property+"', returning 0");
    		return 0;
    	}
    }

    private Attribute getAttributeFromPrincipal( NIDPPrincipal princ, String attrname )
    {
		UserAuthority ua = princ.getAuthority();
		logger.log( dbglevel, "getting attribute {0}.", attrname );
		Attributes attrs = ua.getAttributes( princ , new String[] { attrname } );
		Attribute result = attrs.get( attrname );
		if ( result == null )
		{
			logger.log(dbglevel, "Attribute {0} not found.", attrname);
			result = new BasicAttribute(attrname);
		}
		return result;
    }

	/**
	 * Clear the current user cookie by settings the value to null and the max age to 0. <br/>
	 * The cookie is then added to the HTTP response object.
	 * @param ck the cookie object to clear
	 */
	private void clearCookie(String cookieName) 
	{
		Cookie ck = getCookie(cookieName);
		if ( ck != null )
		{
			ck.setValue(null);
			ck.setMaxAge(0);
			m_Response.addCookie(ck);
		}
	}

	/**
	 * Check the validity of a cookie object in terms of lifetime and/or the timestamp contents.
	 * @param ck the cookie object to check
	 * @return true if the lifetime is greater than 0 or the timestamp contents is in the future, false otherwise
	 */
	private boolean checkCookieValidity(String cookieName) 
	{
		logger.log( dbglevel, "Checking cookie validity");
		Cookie ck = getCookie(cookieName);
		if ( ck != null )
		{
			int lifetime = ck.getMaxAge();
			logger.log( dbglevel, "lifetime: {0}", lifetime );
			logger.log( dbglevel, "contents: {0}", ck.getValue() );
			boolean invalid = isDatePast( ck.getValue() );
			logger.log( dbglevel, "date past: {0}", invalid );
			if ( lifetime > 0 || !invalid )
			{
				return true;
			}
		}
		return false;
	}

	/**
	 * Retrieve the named cookie from the given list of cookies.
	 * @param cookies
	 * @param cookieName
	 * @return
	 */
	private Cookie getCookie(String cookieName) 
	{
		Cookie[] cookies = m_Request.getCookies();
		if ( cookies != null )
		{
			for ( Cookie ck : cookies )
			{
				if ( ck.getName().equals(cookieName) )
					return ck;
			}
		}
		return null;
	}

	private boolean hasUserRegistration( Authenticator authn, String attrName, boolean clear )
	{
		boolean registered = authn.isUserRegistered();
		if ( attrName != null && !attrName.isEmpty() )
		{
			logger.log( dbglevel, "Check re-enrollment status." );
			Attribute attr = getAttributeFromPrincipal(localPrincipal, attrName);
			try
			{
				String value = (String)attr.get();
				if( Boolean.parseBoolean(value) )
				{
					logger.log( dbglevel, "Need to re-enroll user." );
					registered = false;
					if ( clear )
					{
						UserAuthority ua = localPrincipal.getAuthority();
						try {
							ua.modifyAttributes( localPrincipal, new String[]{ reEnrollmentAttribute }, new String[] { "false" } );
						} catch (NIDPException e) {
							logger.log(errlevel, "failed to clear re-enrollment attribute: "+e.getMessage());
						}
					}
				}
			}
			catch (Exception e) {}
		}
		return registered;
	}
}

package nl.idfocus.nam.authentication;

import java.util.ArrayList;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;

import com.novell.nidp.NIDPException;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.NIDPSubject;
import com.novell.nidp.authentication.AuthClassDefinition;
import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.authentication.local.BasicClass;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;

import nl.idfocus.nam.util.LogFormatter;

/**
 * Custom Authentication class for NetIQ Access Manager<br/>
 * <p>
 * The TOTPOrSmsToken class allows attribute-based switching between Time-based OTP authentication and SMS Token authentication.<br/>
 * </p><p>
 * The (boolean or string with true/false) attribute that is used to determine which class is used, is configurable. <br/>
 * When the attribute value is not present or set to 'false', SMS Token authentication is used. When 'true' Time-based OTP authentication is used.<br/>
 * </p>
 * <p>
 * <b>NOTE</b> Properties for a specific authentication class <i>need to be prefixed</i> with either 'totp_' or 'sms_' respectively to be passed on to that class only.
 * A typical example is the <i>JSP</i> property which is usually different for each class. Unprefixed properties are passed on to both classes. 
 * </p>
 * @author IDFocus B.V. (mvreijn@idfocus.nl)
 * @version Tested on NetIQ Access Manager 4.0.x, 4.1.x and 4.2.x
 */
public class TOTPOrSmsToken extends LocalAuthenticationClass 
{
	private static final Logger logger   = LogFormatter.getConsoleLogger( TOTPOrSmsToken.class.getName() );
	private static final Level  loglevel = Level.INFO;
	private static final Level  dbglevel = Level.FINE;
	private static final Level  errlevel = Level.SEVERE;

	/**
	 * By setting this property name on the class or method to a valid attribute name, the boolean value of that attribute <br/>
	 * is used to determine which authentication type is used: 'true' calls TOTPAuth and 'false' or non-present calls SmsToken. <br/>
	 * The default setting is specified in {@link #DEF_SWITCH_ATTR}
	 */
	private static final String PROP_SWITCH_ATTR = "switchAttribute";

	/** Constant to indicate that SMS authentication is to be selected. */
	public static final String SWITCH_ATTR_SMS  = "sms";

	/** Constant to indicate that TOTP authentication is to be selected. */
	public static final String SWITCH_ATTR_TOTP = "totp";

	/**
	 * By setting this property name on the class or method, the debug mode may be enabled. 
	 * This overrides the default specified in {@link #DEF_DEBUG}
	 */
	private static final String PROP_DEBUG       = "DEBUG";

	private static final String DEF_SWITCH_ATTR  = "carLicense";
	private static final String DEF_DEBUG        = "false";

	private final String methodSwitchAttribute;
	private final boolean debugMode;

	private final LocalAuthenticationClass totpAuth;
	private final LocalAuthenticationClass smsAuth;

	/** The prefix for all properties that need to be passed to the TOTPAuth class. */
	private static final String PREFIX_TOTP = "totp_";
	/** The prefix for all properties that need to be passed to the SmsToken class. */
	private static final String PREFIX_SMST = "sms_";

	private NIDPPrincipal localPrincipal;
	private final String sessionUser;

	private static final String LAST_CHANGED_REVISION = "$LastChangedRevision: 81 $";
	private final String revision;

	public TOTPOrSmsToken(Properties props, ArrayList<UserAuthority> stores) 
	{
		super(props, stores);
		this.revision = LAST_CHANGED_REVISION.substring( LAST_CHANGED_REVISION.indexOf(':')+1, LAST_CHANGED_REVISION.lastIndexOf('$') ).trim();
		logger.log( loglevel, "TOTP or SMS Token Authentication Class rev "+revision+" (c) IDFocus B.V. <info@idfocus.nl>" );
		logger.log( loglevel, "Initializing TOTPOrSmsToken" );
		//
		methodSwitchAttribute = props.getProperty( PROP_SWITCH_ATTR , DEF_SWITCH_ATTR );
		debugMode       = Boolean.parseBoolean( props.getProperty( PROP_DEBUG, DEF_DEBUG ) );
		if ( debugMode )
		{
			LogFormatter.setLoggerDebugMode(logger);
		}
		logger.log( dbglevel, "$Id: TOTPOrSmsToken.java 81 2017-02-07 12:28:10Z mvreijn $" );
		// Create authenticators
		logger.log( dbglevel, "Creating TOTP class: "+TOTPAuth.class.getName() );
		final Properties totpProps = filterProperties(props, PREFIX_TOTP, PREFIX_SMST);
		totpAuth = instantiate( TOTPAuth.class.getName(), totpProps );
		logger.log( dbglevel, "Creating SMS class: "+SmsToken.class.getName() );
		final Properties smsProps  = filterProperties(props, PREFIX_SMST, PREFIX_TOTP);
		smsAuth  = instantiate( SmsToken.class.getName(), smsProps  );
		// Last step is to find the user
		sessionUser = getProperty("findSessionUser");
		logger.log( dbglevel, "Session user: "+sessionUser );
		logger.log( loglevel, "Done." );
	}

	private Properties filterProperties( Properties props, String includePrefix, String excludePrefix )
	{
		Properties result = new Properties();
		// Read setup properties
		for( Map.Entry<Object, Object> entry : props.entrySet() )
		{
			String key = (String)entry.getKey();
			if      ( key.startsWith(includePrefix) )
			{
				result.put( key.substring(includePrefix.length()), entry.getValue() );
			}
			else if ( !key.startsWith(excludePrefix) )
			{
				// Possible NPE on specific NAM internal properties? Only for non-strings probably!
				try
				{
					result.putIfAbsent(key, entry.getValue());
				}
				catch (NullPointerException e)
				{
					logger.log( errlevel, String.format( "[Expected Behavior] NPE while handling %s property value", key ) );
				}
			}
		}
		// DEBUG Property names
		if ( debugMode )
		{
			for( Map.Entry<Object, Object> entry : result.entrySet() )
			{
				logger.log( dbglevel, "[DBG] "+includePrefix+" property \'"+entry.getKey()+"\': "+entry.getValue() );
			}
		}
		return result;
	}

	@Override
	public String getType() 
	{
		return AuthnConstants.TOKEN;
	}

	@Override
	protected int doAuthenticate()
	{
		logger.log( loglevel, "Starting TOTPOrSmsToken Authentication" );
		/*
		 * Determine active class
		 */
		localPrincipal = resolveUserPrincipal();
		LocalAuthenticationClass activeClass;
		String method = getMethodSelection(localPrincipal);
		logger.log( dbglevel, String.format( "User selected %s as authentication method.", method ) );
		if ( method.equals(SWITCH_ATTR_TOTP) )
			activeClass = totpAuth;
		else if ( method.equals(SWITCH_ATTR_SMS) )
			activeClass = smsAuth;
		else
			return NOT_AUTHENTICATED;
		logger.log( dbglevel, "Active class: "+activeClass.getClass().getName() );
		/*
		 * Start authentication
		 */
		activeClass.initializeRequest( m_Request, m_Response, m_Session, m_SessionData, isFirstCallAfterPrevMethod(), getReturnURL() );
		int authStatus = activeClass.authenticate();
		if ( authStatus == AUTHENTICATED )
		{
			logger.log( dbglevel, "Authentication succeeded." );
			setPrincipal( activeClass.getPrincipal() );
			m_Credentials = activeClass.getCredentials();
		}
		else if ( authStatus == SHOW_JSP )
		{
			m_PageToShow = activeClass.getPageToShow();
			return authStatus;
		}
		else
		{
			if ( authStatus == PWD_EXPIRING )
			{
				logger.log( dbglevel, "Authentication succeeded conditionally." );
				m_PasswordException = activeClass.getPasswordException();
				m_ExpiredPrincipal = activeClass.getExpiredPrincipal();
				setPrincipal(activeClass.getPrincipal());
			}
			else
			{
				logger.log( errlevel, "Authentication failed with status "+authStatus+"." );
			}
		}
		return authStatus;
	}

	private LocalAuthenticationClass instantiate( String name, Properties props )
	{
		try {
			AuthClassDefinition rawDefinition = new AuthClassDefinition( "TOTPOrSmsToken", name, props );
	        return rawDefinition.getInstance( m_UserStores, props );
		} catch (NIDPException e) {
			logger.log( errlevel, "Error "+e.getErrorID()+" instantiating "+name+": "+e.getMessage() );
		}
		return new BasicClass(props, m_UserStores);
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
	                    logger.log( dbglevel, "found "+allNidpPrincipals.length+" principal(s) in session subject");
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

    private Attribute getAttr( NIDPPrincipal princ, String attrname )
    {
		UserAuthority ua = princ.getAuthority();
		logger.log( dbglevel, "getting attribute: "+attrname );
		Attributes attrs = ua.getAttributes( princ , new String[] { attrname } );
		logger.log( dbglevel, "getting attribute");
		Attribute result = attrs.get( attrname );
		if ( result == null )
		{
			logger.log(dbglevel, "Attribute "+attrname+" not found." );
			result = new BasicAttribute(attrname);
		}
		return result;
    }

    private String getMethodSelection( NIDPPrincipal princ )
    {
		logger.log( dbglevel, "getting attribute: "+methodSwitchAttribute );
    	Attribute attr = getAttr(princ, methodSwitchAttribute);
    	try
    	{
    		return ((String)attr.get()).toLowerCase();
    	} catch (NoSuchElementException | NamingException | NullPointerException e) {
    		logger.log( errlevel, "Error getting attribute value: "+e.getMessage() );
    		return "";
    	}
    }
}

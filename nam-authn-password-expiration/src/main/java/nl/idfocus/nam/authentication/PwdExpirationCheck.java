/**
 *
 */
package nl.idfocus.nam.authentication;

import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.LdapContext;

import nl.idfocus.nam.password.PwdConstants;
import nl.idfocus.nam.password.PwdPolicy;
import nl.idfocus.nam.util.LogFormatter;

import com.novell.nam.common.ldap.jndi.JNDIUserStore;
import com.novell.nam.common.ldap.jndi.JNDIUserStoreReplica;
import com.novell.nidp.NIDPConstants;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.NIDPSession;
import com.novell.nidp.NIDPSubject;
import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.authentication.local.PageToShow;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.authority.ldap.LDAPUserAuthority;
import com.novell.nidp.common.util.net.client.NIDP_SSLSocketFactory;
import com.novell.nidp.liberty.wsc.cache.WSCCacheEntry;
import com.novell.nidp.liberty.wsc.cache.pushed.WSCCachePushed;
import com.novell.nidp.liberty.wsc.cache.pushed.WSCCachePushedCache;
import com.novell.nidp.liberty.wsc.cache.pushed.WSCCachePushedCacheSet;
import com.novell.nidp.liberty.wsc.query.WSCQSSToken;
import com.novell.nidp.liberty.wsf.idsis.ssservice.schema.SSSecretEntry;
import com.novell.security.nmas.NMASConstants;
import com.novell.security.nmas.mgmt.NMASPwdException;
import com.novell.security.nmas.mgmt.NMASPwdMgr;

/**
 * Custom Authentication class for NetIQ Access Manager<br/>
 * <p>
 * The main functionality is to check for an expired or expiring password for the principal currently logging in. <br/>
 * Once triggered, a JSP is displayed that explains the applicable password policy and prompts the user for a new password. <br/>
 * </p>
 * 
 * @author IDFocus B.V. (mvreijn@idfocus.nl)
 * @version Tested on NetIQ Access Manager 4.0, 4.1 and 4.2
 * @since NAM 3.2
 * 
 */
public class PwdExpirationCheck extends LocalAuthenticationClass
{
	private static final String JSP_DEFAULT = "changepwd";
	// Logging
	private static Logger logger = LogFormatter.getConsoleLogger( PwdExpirationCheck.class.getName() );
	private Level loglevel = Level.INFO;
	private Level logerror = Level.SEVERE;
	// JSP / Session settings
	public final String SETTING_ALLOW_SKIP = "allowskip";
	// Constants: option names
	private final String MODE_ID                 = "Mode";
	private final String TRIGGER_GRACE_ID        = "GracetimeNumber";
	private final String TRIGGER_PREWARN_ID      = "PreWarnIntervals";
	private final String PARAM_SKIP_GRACE_MIN_ID = "SkipUntilGraceLogin";
	private final String PARAM_SKIP_ALLOW_ID     = "AllowSkipButton";
	private final String ATTR_EXP_ID             = "ExpirationAttribute";
	private final String ATTR_EXPINT_ID          = "IntervalAttribute";
	private final String ATTR_GRACE_ID           = "GracetimeAttribute";
	private final String FIELD_NEWPWD_ID         = "NewPasswordField";
	private final String FIELD_CHKPWD_ID         = "CheckPasswordField";
	// Constants: default values
	private final String MODE_DEFAULT = "grace";
	private final String[] MODES = { "grace", "prewarn" };
	private final String TRIGGER_GRACE_DEFAULT = "2";
	private final String TRIGGER_PREWARN_DEFAULT = "1,3,5";
	private final String PARAM_SKIP_GRACE_MIN_DEFAULT = "0";
	private final String PARAM_SKIP_ALLOW_DEFAULT = "true";
	private final String ATTR_EXP_DEFAULT = "passwordExpirationTime";
	private final String ATTR_EXPINT_DEFAULT = "passwordExpirationInterval";
	private final String ATTR_GRACE_DEFAULT = "loginGraceRemaining";
	private final String FIELD_NEWPWD_DEFAULT = "Ecom_New_Password";
	private final String FIELD_CHKPWD_DEFAULT = "Ecom_Check_Password";
	// TODO make this configurable
	private final String PARAM_DATE_FMT = "yyyyMMddHHmmss'Z'";
	// Variables
	private final String MODE;
	private final String TRIGGER_GRACE;
	private final String TRIGGER_PREWARN;
	private final String PARAM_SKIP_GRACE_MIN;
	private final String PARAM_SKIP_ALLOW;
	private final String ATTR_EXP;
	private final String ATTR_EXPINT;
	private final String ATTR_GRACE;
	private final String FIELD_NEWPWD;
	private final String FIELD_CHKPWD;
	private NIDPPrincipal local_Principal;
	private final String sessionUser;
	private Attributes expAttrs;

	private String nmasError = "";

	private static final String PKGBUILD = PwdExpirationCheck.class.getPackage().getImplementationVersion();

	/**
	 * The default constructor for LocalAuthenticationClass
	 * @param props
	 * @param stores
	 */
	public PwdExpirationCheck( Properties props, ArrayList<UserAuthority> stores )
	{
		super( props, stores );
		logger.log( loglevel, "Password Expiration Authentication Class build "+PKGBUILD+" (c) IDFocus B.V. <info@idfocus.nl>" );
		logger.log( loglevel, "Initializing Password Expiration Check.");
		// Read setup properties
		MODE = props.getProperty( MODE_ID, MODE_DEFAULT );
		TRIGGER_GRACE = props.getProperty( TRIGGER_GRACE_ID, TRIGGER_GRACE_DEFAULT );
		TRIGGER_PREWARN = props.getProperty( TRIGGER_PREWARN_ID, TRIGGER_PREWARN_DEFAULT );
		PARAM_SKIP_GRACE_MIN = props.getProperty( PARAM_SKIP_GRACE_MIN_ID , PARAM_SKIP_GRACE_MIN_DEFAULT );
		PARAM_SKIP_ALLOW = props.getProperty( PARAM_SKIP_ALLOW_ID , PARAM_SKIP_ALLOW_DEFAULT );
		ATTR_EXP = props.getProperty( ATTR_EXP_ID, ATTR_EXP_DEFAULT );
		ATTR_EXPINT = props.getProperty( ATTR_EXPINT_ID, ATTR_EXPINT_DEFAULT );
		ATTR_GRACE = props.getProperty( ATTR_GRACE_ID, ATTR_GRACE_DEFAULT );
		FIELD_NEWPWD = props.getProperty( FIELD_NEWPWD_ID, FIELD_NEWPWD_DEFAULT );
		FIELD_CHKPWD = props.getProperty( FIELD_CHKPWD_ID, FIELD_CHKPWD_DEFAULT );
		sessionUser = getProperty("findSessionUser");
	}

	@Override
	public String getType()
	{
		return AuthnConstants.PASSWORD;
	}

	/**
	 * implement doAuthenticate()n in the following way:<br/>
	 * check for expired password (and grace logins),
	 * redirect to JSP for new password,
	 * change password in the user store and in the current credential set.
	 * @return returns the status of the authentication process which is one of AUTHENTICATED or SHOW_JSP<br/>
	 */
	@Override
	protected int doAuthenticate()
	{
		logger.log( loglevel, "password expiration check request");

		// Get Principal.
		local_Principal = getUserPrincipal();
		expAttrs = getExpirationAttrs();

		// Prompt the user if necessary
		if ( isFirstCallAfterPrevMethod() )
		{
			if ( isUserPrompted( expAttrs ) )
			{
				logger.log( loglevel, "prompting user for pwd change");
				boolean skipAllowed = allowSkipButton();
				// add allow skip setting to session to ensure consistency during different actions
				m_Request.getSession(true).setAttribute(SETTING_ALLOW_SKIP, skipAllowed);
				prepareJsp( null, skipAllowed );
				return SHOW_JSP;
			}
			else
			{
				return AUTHENTICATED;
			}
		}
		// Check skip button and allow setting from session
		String skip = m_Request.getParameter( "pwdsbutton" );
		boolean skipAllowed = (Boolean) m_Request.getSession().getAttribute(SETTING_ALLOW_SKIP);
		if ( skip != null && skip.equalsIgnoreCase("overslaan") && skipAllowed )
		{
			return AUTHENTICATED;
		}

		// Check new password
		String newpwd = m_Request.getParameter( FIELD_NEWPWD );
		String chkpwd = m_Request.getParameter( FIELD_CHKPWD );
		if ( newpwd != null && chkpwd != null && newpwd.equals(chkpwd) )
		{
			// OK, change password
			if ( changeNmasPassword( local_Principal, newpwd ) )
			{
				setPrincipalPassword( newpwd );
				// Done.
				return AUTHENTICATED;
			}
			else
			{
				// TODO get text from multi-language properties
				prepareJsp( "wachtwoord wijzigen mislukt: "+nmasError, skipAllowed );
				return SHOW_JSP;
			}
		}
		else
		{
			// TODO get text from multi-language properties
			prepareJsp( "wachtwoorden zijn niet ingevuld of niet gelijk", skipAllowed );
			return SHOW_JSP;
		}
	}

	/**
	 * Check if the current user needs to be prompted for password change.<br/>
	 * This is checked using the LDAP expiration attribute and optionally the number of grace logins remaining. <br/>
	 * The default behavior is: no prompt if attribute is not present.
	 * @return boolean for yes or no
	 */
	private boolean isUserPrompted( Attributes attrs )
	{
		try 
		{
			logger.log( loglevel, "getting attribute");
			Attribute expAttr = attrs.get( ATTR_EXP );
			logger.log( loglevel, "getting values");
			if ( expAttr != null && expAttr.size() > 0 )
			{
				Object expValue = expAttr.get();
				if ( expValue != null && expValue instanceof String )
				{
					String strExpValue = (String) expValue;
					logger.log( loglevel, "value found: "+strExpValue+" for mode "+MODE);
					if ( MODE.equals( MODES[0] ) )
					{
						logger.log( loglevel, "mode "+MODES[0]);
						if ( isDatePast( strExpValue ) )
						{
							logger.log( loglevel, "password is expired");
							Attribute graceAttr = attrs.get( ATTR_GRACE );
							if ( graceAttr != null && graceAttr.size() > 0 )
							{
								Object graceValue = graceAttr.get();
								if ( graceValue != null && graceValue instanceof String )
								{
									String strGraceValue = (String) graceValue;
									logger.log( loglevel, "grace login check if "+TRIGGER_GRACE+" is equal or more than "+strGraceValue);
									if( Integer.parseInt( TRIGGER_GRACE ) >= Integer.parseInt( strGraceValue ) )
										return true;
								}
							}
						}
					}
					else if ( MODE.equals( MODES[1] ) )
					{
						logger.log( loglevel, "mode "+MODES[1]);
						String daysToGo = getDaysAfter( strExpValue );
						// FIXME should just be one number, when to start prompting.
						for ( String trigger : TRIGGER_PREWARN.split( "," ) )
						{
							if ( Integer.parseInt( trigger.trim() ) <= Integer.parseInt( daysToGo ) )
								return true;
						}
					}
				}
			}
		} catch (NamingException e) {
			logger.log( logerror,  "NamingException: "+e.getExplanation() );
		} catch (NumberFormatException e) {
			logger.log( logerror,  "NumberFormatException: "+e.getMessage() );
		} catch (Exception e) {
			logger.log( logerror,  "Exception: "+e.getMessage() );
		}
		return false;
	}

	/**
	 * Check if the given date String in yyyyMMddHHmmssZ format is in the past.
	 * @param dateStr Date as a String in yyyyMMddHHmmssZ format
	 * @return true for in the past, false for in the future.
	 */
	private boolean isDatePast( String dateStr )
	{
		SimpleDateFormat format = new SimpleDateFormat( PARAM_DATE_FMT );
		Calendar cal = Calendar.getInstance();
		cal.setTimeZone( TimeZone.getTimeZone( "UTC" ) );
		Date today = cal.getTime();
		logger.log( loglevel, "today: "+today.toString() );
		try {
			Date check = format.parse( dateStr );
			logger.log( loglevel, "expdate: "+check.toString() );
			return today.after( check );
		} catch (ParseException e) {
			logger.log( logerror, "Date parsing exception: "+e.getMessage()+" for value "+dateStr+" at position "+e.getErrorOffset() );
		} catch (NullPointerException e) {
			logger.log( logerror, "Date parsing exception: "+e.getMessage()+" for value "+dateStr );
		}
		return false;
	}

    /**
     * Returns the number of days between now and the expiration date. 
     * @return number of days as a String, or null if the expiration date is in the past
     */
	private String getDaysAfter( String dateStr ) 
	{
		SimpleDateFormat format = new SimpleDateFormat( PARAM_DATE_FMT );
		Calendar cal = Calendar.getInstance();
		cal.setTimeZone( TimeZone.getTimeZone( "UTC" ) );
		Date today = cal.getTime();
		try {
			Date expdate = format.parse( dateStr );
			if ( expdate.after( today ) )
			{
				long daysNow = today.getTime() / (24 * 60 * 60 * 1000);
				long daysThen = expdate.getTime() / (24 * 60 * 60 * 1000);
				return Long.toString( daysThen - daysNow + 1 );
			}
		} catch (ParseException e) {
			logger.log( logerror,  "ParseException: "+e.getMessage() );
		} catch (Exception e) {
			logger.log( logerror,  "Exception: "+e.getMessage() );
		}
		return null;
	}

	/**
	 * Find the NIDPPrincipal for our subject by any means
	 * @return NIDPPrincipal object or <i>null</i> if it cannot be determined
	 */
    private NIDPPrincipal getUserPrincipal()
    {
        logger.log( loglevel, "getting principal from properties (contract)");
        NIDPPrincipal nidpprincipal = (NIDPPrincipal) m_Properties.get("Principal");

        if ( nidpprincipal == null )
        {
        	logger.log( loglevel, "getting user from session");
            if(sessionUser != null)
            {
                if( m_Session.isAuthenticated() )
                {
                    NIDPSubject nidpsubject = m_Session.getSubject();
                    NIDPPrincipal anidpprincipal[] = nidpsubject.getPrincipals();
                    if(anidpprincipal.length == 1)
                    {
                        nidpprincipal = anidpprincipal[0];
                        logger.log( loglevel,  ( new StringBuilder() ).append("principal retrieved from authenticated session").append( nidpprincipal.getUserIdentifier() ).toString() );
                        setPrincipal(nidpprincipal);
                    }
                }
                if(nidpprincipal == null)
                	logger.log( loglevel, "no principal in session");
            }
        }
        else
        {
        	logger.log( loglevel, (new StringBuilder()).append("retrieved principal from properties").append(nidpprincipal.getUserIdentifier()).toString());
            setPrincipal(nidpprincipal);
        }
        return nidpprincipal;
    }

    /**
     * Change a principal's password in the LDAP user store using the NMAS API. <br/>
     * This ensures that the password is changed by the user and not by an administrator. <br/>
     * Relies on eDirectory!
     * @param princ
     * @param password
     * @return true if the change succeeded
     */
    private boolean changeNmasPassword( NIDPPrincipal princ, String password )
    {
    	boolean result = false;
    	LdapContext ctx = getLdapContextForPrincipalUserstore( princ );
		try {
			NMASPwdMgr passwordMgr = new NMASPwdMgr( ctx );
			String oldPwd = passwordMgr.getPwd( "", princ.getUserIdentifier() );
			passwordMgr.changePwd( "", princ.getUserIdentifier() , oldPwd, password );
			logger.log( loglevel, "NMAS Password change successful" );
			result = true;
		} catch (NMASPwdException e) {
			logger.log( loglevel, "NMAS Password change error: " + e.toString() + " code: " + e.getNmasRetCode());
			// Return correct error message
			if ( e.getNmasRetCode() == -216 ) // TOO SHORT
			{
				nmasError = PwdConstants.PASSWORD_ERROR_TOO_SHORT.getMessage();
				result = false;
			}
			else if ( e.getNmasRetCode() == NMASConstants.NMAS_E_PASSWORD_TOO_LONG )
			{
				nmasError = PwdConstants.PASSWORD_ERROR_TOO_LONG.getMessage();
				result = false;
			}
			else if ( e.getNmasRetCode() == NMASConstants.NMAS_E_PASSWORD_UPPER_MIN )
			{
				nmasError = PwdConstants.PASSWORD_ERROR_UPPER_MIN.getMessage();
				result = false;
			}
			else if ( e.getNmasRetCode() == NMASConstants.NMAS_E_PASSWORD_LOWER_MIN )
			{
				nmasError = PwdConstants.PASSWORD_ERROR_LOWER_MIN.getMessage();
				result = false;
			}
			else if ( e.getNmasRetCode() == NMASConstants.NMAS_E_PASSWORD_NUMERIC_MIN )
			{
				nmasError = PwdConstants.PASSWORD_ERROR_NUMERIC_MIN.getMessage();
				result = false;
			}
			else if ( e.getNmasRetCode() == NMASConstants.NMAS_E_PASSWORD_SPECIAL_DISALLOWED )
			{
				nmasError = PwdConstants.PASSWORD_ERROR_SPECIAL_DISALLOWED.getMessage();
				result = false;
			}
			else if ( e.getNmasRetCode() == NMASConstants.NMAS_E_PASSWORD_SPECIAL_MIN )
			{
				nmasError = PwdConstants.PASSWORD_ERROR_SPECIAL_MIN.getMessage();
				result = false;
			}
			else if ( e.getNmasRetCode() == -215 ) // IN HISTORY
			{
				nmasError = PwdConstants.PASSWORD_ERROR_IN_HISTORY.getMessage();
				result = false;
			}
			else if ( e.getNmasRetCode() == NMASConstants.NMAS_E_PASSWORD_HISTORY_FULL )
			{
				nmasError = PwdConstants.PASSWORD_ERROR_HISTORY_FULL.getMessage();
				result = false;
			}
			else 
			{
				nmasError = PwdConstants.PASSWORD_ERROR_UNKNOWN.getMessage() + " ("+e.getNmasRetCode()+")";
				logger.log( logerror, "Unknown NMAS return code: " + e.getNmasRetCode());
			}
		} finally {
			try {
				ctx.close();
			} catch (NamingException e) {}
		}
		return result;
    }

    /**
     * Set the LDAP password on the current principal object. <br/>
     * This ensures that the user session is established with the new password. 
     * @param password the new password
     */
	private void setPrincipalPassword( String password )
	{
		clearCredentials();
		SSSecretEntry sssecretentry = new SSSecretEntry( "UserPassword", password );
		addLDAPCredentials();
		addCredential( WSCQSSToken.SS_SecretEntry_LDAPCredentials_UserPassword, sssecretentry );
		cachePassword( m_Session, password );
//		setPrincipal(local_Principal);	
	}

	/**
	 * Push the given password value to the IDP cache. 
	 * 
	 * @param session IDP session object for the current principal
	 * @param value the password value to push
	 */
	private void cachePassword( NIDPSession session, String value )
	{
		WSCCacheEntry[] entries = { new WSCCacheEntry( "", WSCQSSToken.SS_SecretEntry_LDAPCredentials_UserPassword.getTokenUniqueId(), value ) };
		WSCCachePushed cachePushed = WSCCachePushed.getInstance();
        WSCCachePushedCache cache = cachePushed.getCache(session.getID());
        if ( cache == null )
        {
        	cache = new WSCCachePushedCache();
        }
    	cache.add(new WSCCachePushedCacheSet(entries, null), WSCCachePushedCache.ALLOW_OVERRIDE);
        cachePushed.addCache(session.getID(), cache);
	}

	private void prepareJsp( String error, boolean skip )
	{
		String jsp = getProperty( AuthnConstants.PROPERTY_JSP );
		if ( jsp == null || jsp.length() == 0 )
		{
			jsp = JSP_DEFAULT;
		}
		m_PageToShow = new PageToShow( jsp );
		m_PageToShow.addAttribute( NIDPConstants.ATTR_URL, ( getReturnURL() != null ? getReturnURL() : m_Request.getRequestURL().toString() ) );
		m_PageToShow.addAttribute( "mode", MODE );
		m_PageToShow.addAttribute( "pwdpolicy", getNMASPolicy( getUserPrincipal() ) );
		if ( getAuthnRequest() != null && getAuthnRequest().getTarget() != null )
		{
			m_PageToShow.addAttribute( "target", getAuthnRequest().getTarget() );
		}
		if ( error != null )
		{
			m_PageToShow.addAttribute( "error", error );
		}
		m_PageToShow.addAttribute( "numtogo", Integer.toString( getNumToGo( expAttrs ) ) );
		m_PageToShow.addAttribute( SETTING_ALLOW_SKIP, skip );			
	}

	/**
	 * Read the password policy for a given user and return the password policy rules as localized text. 
	 * 
	 * @param princ the NIDPPrincipal representing the current user 
	 * @return an array of strings that represent the password policy
	 */
	private String[] getNMASPolicy( NIDPPrincipal princ ) 
	{
		List<PwdPolicy> attributes = new ArrayList<>();
    	LdapContext ctx = getLdapContextForPrincipalUserstore( princ );
		try 
		{
			NMASPwdMgr passwordMgr = new NMASPwdMgr( ctx );
			String policyDn = passwordMgr.getPwdPolicyDN( "", princ.getUserIdentifier() );
			Attributes rawAttrs = ctx.getAttributes( policyDn, PwdPolicy.getAttributeNames() );
			NamingEnumeration<? extends Attribute> attrs = rawAttrs.getAll();
			while( attrs.hasMore() )
			{
				Attribute attr = attrs.next();
				PwdPolicy rule = PwdPolicy.resolveValue( attr.getID() );
				if ( rule != null )
				{
					// FIXME will not work for binary values like exclude list and complexity rules
					Object value = attr.get();
					if ( value instanceof String )
						rule.setValue( (String) value );
					else
						rule.setValue( new String( (byte[])value, "UTF-8" ) );
					attributes.add(rule);
				}	
			}
		} 
		catch (NMASPwdException e) 
		{
			logger.log(logerror, "Resolving policy settings encountered "+e.getClass().getName()+": "+e.getMessage()+" code: "+e.getNmasRetCode() );
		} 
		catch (NamingException e) 
		{
			logger.log(logerror, "Resolving policy settings encountered "+e.getClass().getName()+": "+e.getExplanation() );
		} 
		catch (UnsupportedEncodingException e) 
		{
			// This won't happen but we have to catch it to satisfy the compiler
			logger.log(logerror, "Resolving policy settings encountered "+e.getClass().getName()+": "+e.getMessage() );
		}
		finally
		{
			try {
				ctx.close();
			} catch (NamingException e) {}
		}
		// Using sort without Comparator on enum sorts in the enum order
		Collections.sort( attributes );
		// support for multiple browser locales
		Locale loc = this.m_Request.getLocale();
		return PwdPolicy.getMessageList( attributes, loc );
	}

	private boolean allowSkipButton()
	{
		// setting param to false overrides everything
		if ( !Boolean.parseBoolean( PARAM_SKIP_ALLOW ) )
		{
			return false;
		}
		else if ( MODE.equals( MODES[0] ) )
		{
			// if grace, check min against numtogo
			try
			{
				if ( getNumToGo( expAttrs ) <= Integer.parseInt( PARAM_SKIP_GRACE_MIN ) )
				{
					return false;
				}
			}
			catch ( NumberFormatException e ) {}
		}
		else if ( MODE.equals( MODES[1] ) )
		{
			// if prewarn, check if numtogo = 0
			if ( getNumToGo( expAttrs ) == 0 )
			{
				return false;
			}
		}
		return true;
	}

	private Attributes getExpirationAttrs()
	{
		Attributes attrs = null;
		try 
		{
			UserAuthority ua = local_Principal.getAuthority();
			logger.log( loglevel, "getting principal attributeset");
			attrs = ua.getAttributes( local_Principal , new String[] { ATTR_EXP, ATTR_EXPINT, ATTR_GRACE } );
		} catch (Exception e) {
			logger.log( logerror,  "Exception: "+e.getMessage() );
		}
		return attrs;
	}

	private int getNumToGo( Attributes expAttrs )
	{
		String numtogo = null;
		if ( MODE.equals( MODES[0] ) )
		{
			try {
				Attribute expGrace = expAttrs.get( ATTR_GRACE );
				numtogo = (String)expGrace.get();
			} catch (NamingException e) {
				logger.log(logerror, "Error while getting grace login count: "+e.getExplanation() );
			}
		}
		else if ( MODE.equals( MODES[1] ) )
		{
			try {
				Attribute expDate = expAttrs.get( ATTR_EXP );
				numtogo = getDaysAfter( (String)expDate.get() ) ;
			} catch (NamingException e) {
				logger.log(logerror, "Error while getting days to go: "+e.getExplanation() );
			}
		}
		if ( numtogo != null )
		{
			try
			{
				return Integer.parseInt(numtogo);
			}
			catch (NumberFormatException e) {}
		}
		return -1;
	}

	private LdapContext getLdapContextForPrincipalUserstore(NIDPPrincipal principal)
	{
		LDAPUserAuthority la = (LDAPUserAuthority) principal.getAuthority();
		JNDIUserStore userStore = la.getStore();
		return getLdapContextForUserstore(userStore);
	}

	private LdapContext getLdapContextForUserstore(JNDIUserStore userStore)
	{
		if ((userStore == null) || (!userStore.isEDir())) return null;

		JNDIUserStoreReplica[] userStoreReplicas = userStore.getUserStoreReplicas();
		int replicaCount = userStoreReplicas.length;

		String bindpw = userStore.getAdminPassword();
		String bindname = userStore.getAdminUsername();

		for (int rCount = 0; rCount < replicaCount; rCount++)
		{
			LdapContext lc = getLdapContextForReplica(userStoreReplicas[rCount], bindname, bindpw);
			if (lc != null) return lc;
		}
		return null;
	}

	private LdapContext getLdapContextForReplica(JNDIUserStoreReplica replica, String bindName, String bindPwd)
	{
		String host = replica.getHost();
		int port = replica.getPort();
		String url = host + ":" + port + "/";
		Hashtable<String,String> env = new Hashtable<String,String>();
		env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
		env.put("java.naming.provider.url", url);
		env.put("java.naming.security.protocol", "ssl");
		env.put("java.naming.security.authentication", "simple");
		env.put("java.naming.security.principal", bindName);
		env.put("java.naming.security.credentials", bindPwd);
		env.put("java.naming.ldap.factory.socket", NIDP_SSLSocketFactory.class.getName());
		DirContext ctx = null;
		DirContext jndiCtx = null;
		try {
			ctx = new InitialDirContext(env);
		} catch (NamingException e) {
			e.printStackTrace();
			return null;
		}
		try
		{
			jndiCtx = (DirContext)ctx.lookup("");
		} catch (NamingException e1) {
			e1.printStackTrace();
			return null;
		}

		LdapContext ldapCtx = (LdapContext)jndiCtx;
		return ldapCtx;
	}

}

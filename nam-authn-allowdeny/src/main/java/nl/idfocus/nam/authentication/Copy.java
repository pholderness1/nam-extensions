package nl.idfocus.nam.authentication;

import java.util.ArrayList;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.authority.ldap.LDAPPrincipal;
import com.novell.nidp.logging.NIDPLog;
import com.novell.nidp.logging.NIDPLogDecorators;

import nl.idfocus.nam.util.ExistingPrincipalResolver;

/**
 * The <b>Copy</b> Authentication Class returns a successful authentication to the IDP when a previous principal was found. 
 * This class may be used as secondary authentication in cases where 'Identifies User' is mandatory such as a contract with X509 or NAAF. <br/>
 * Combinations are possible with other classes such as the <code>Password</code> built-in class.
 * </p><p>
 * The class attempts to extract the previously identified principal from the session,  <br/> 
 * This user is then passed to the IDP as the authenticated principal. <br/>
 * </p><p>
 * <b>NOTE:</b> When no anonymous user is configured, a fake principal is generated; the IDP may fail the authentication, depending on settings such as "identifies user" or subsequent classes such as <code>PasswordFetch</code>. YMMV. 
 * </p>
 * 
 * @author mvreijn@idfocus.nl
 * @version Tested on NAM 4.x
 */
public class Copy extends LocalAuthenticationClass 
{

	public Copy(Properties props, ArrayList<UserAuthority> stores) 
	{
		super(props, stores);
	}

	@Override
	public String getType() 
	{
		return AuthnConstants.OTHER;
	}

	@Override
	protected int doAuthenticate() 
	{
		Logger log = NIDPLog.getAppLog();
		if ( NIDPLog.isLoggable(log, Level.INFO) )
			log.log(Level.INFO, "{0} Copy Principal", new NIDPLogDecorators("IDFocus#", NIDPLogDecorators.AMDEVICE_PREFIX, NIDPLogDecorators.AMAUTH_PREFIX));
        NIDPPrincipal currentPrincipal = ExistingPrincipalResolver.resolveUserPrincipal(this, m_Properties, m_Session);
		if ( currentPrincipal != null )
		{
			setPrincipal( currentPrincipal );
			addLDAPCredentials();
			try {
			    String userName = ((LDAPPrincipal)currentPrincipal).getUserName();
			    setUserId(userName);
			} catch (ClassCastException e) {
			    log.log(Level.SEVERE, "Principal is not an LDAPPrincipal", e);
			}
			return AUTHENTICATED;
		}
		return NOT_AUTHENTICATED;
	}

}

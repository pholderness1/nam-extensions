package nl.idfocus.nam.authentication;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.authentication.AuthnConstants;
import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.authority.ldap.LDAPPrincipal;
import com.novell.nidp.common.authority.ldap.LdapGUID;
import com.novell.nidp.logging.NIDPLog;
import com.novell.nidp.logging.NIDPLogDecorators;

/**
 * The <b>Allow</b> Authentication Class always returns a successful authentication to the IDP. 
 * This class may be used as fallback in cases where authentication is optional such as a website homepage. <br/>
 * Combinations are necessary with other classes such as the <code>Kerberos</code> or <code>ChainedAuth</code> modules.
 * </p><p>
 * The optional parameter <code>AnonymousUserDn</code> allows an anonymous (real) LDAP user DN to be specified. <br/> 
 * This user is then passed to the IDP as the authenticated principal. <br/>
 * </p><p>
 * <b>NOTE:</b> When no anonymous user is configured, a fake principal is generated; the IDP may fail the authentication, depending on settings such as "identifies user" or subsequent classes such as <code>PasswordFetch</code>. YMMV. 
 * </p>
 * 
 * @author mvreijn@idfocus.nl
 * @version Tested on NAM 4.x
 */
public class Allow extends LocalAuthenticationClass 
{
	/** Property name for the optional anonymous user DN */
	private static final String ANON_KEY = "AnonymousUserDn";
	private final String anonymousPrincipal;
	
	public Allow(Properties props, ArrayList<UserAuthority> stores) 
	{
		super(props, stores);
		anonymousPrincipal = props.getProperty(ANON_KEY);
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
		if ( NIDPLog.isLoggable(log, Level.INFO))
			log.log(Level.INFO, "Allow Authentication", new NIDPLogDecorators("IDFocus#", NIDPLogDecorators.AMDEVICE_PREFIX, NIDPLogDecorators.AMAUTH_PREFIX));
		if ( anonymousPrincipal != null && !anonymousPrincipal.isEmpty() )
			setPrincipal( createAnonymousPrincipal() );
		else
			setPrincipal( createBogusPrincipal() );
		return AUTHENTICATED;
	}

	private NIDPPrincipal createBogusPrincipal() 
	{
		UUID uuid = UUID.randomUUID();
		ByteBuffer bb = ByteBuffer.wrap(new byte[16]);
		bb.putLong(uuid.getMostSignificantBits());
		bb.putLong(uuid.getLeastSignificantBits());
		LdapGUID guid = new LdapGUID(bb.array());
		// Zonder '-' werkt het schijnbaar ook: "f788e013e90b48eb9e0a4037fab7fee7"

		return new LDAPPrincipal(m_UserStores.get(0), guid.getAsHexString(), "cn="+guid.getAsHexString()+",o=bogus");
	}

	private NIDPPrincipal createAnonymousPrincipal() 
	{
		for( UserAuthority store : m_UserStores )
		{
			NIDPPrincipal principal = store.getPrincipalByUniqueName(anonymousPrincipal, m_Credentials);
			if( principal != null )
				return principal;
		}
		// Fallback is a non-verified principal reference
		return new LDAPPrincipal(m_UserStores.get(0), anonymousPrincipal, anonymousPrincipal);
	}

}

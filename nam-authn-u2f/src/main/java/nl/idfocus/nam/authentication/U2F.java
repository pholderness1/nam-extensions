package nl.idfocus.nam.authentication;

import java.util.ArrayList;
import java.util.Properties;

import com.novell.nidp.authentication.local.LocalAuthenticationClass;
import com.novell.nidp.common.authority.UserAuthority;

public class U2F extends LocalAuthenticationClass
{

	/**
	 * @see https://developers.yubico.com/java-u2flib-server/
	 * @see https://developers.yubico.com/java-u2flib-server/u2flib-server-demo/
	 * @see https://developers.yubico.com/U2F/Libraries/Using_a_library.html
	 * @param props
	 * @param stores
	 */
	public U2F(Properties props, ArrayList<UserAuthority> stores)
	{
		super(props, stores);
		// TODO Auto-generated constructor stub
	}

	
}

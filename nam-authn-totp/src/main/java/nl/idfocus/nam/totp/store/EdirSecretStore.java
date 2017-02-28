package nl.idfocus.nam.totp.store;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

import com.novell.nam.common.ldap.jndi.JNDIUserStoreReplica;
import com.novell.nam.common.ldap.jndi.JNDIUserStoreReplicaConnection;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.common.authority.UserAuthority;
import com.novell.nidp.common.authority.ldap.LDAPUserAuthority;
import com.novell.security.sso.SSException;
import com.novell.security.sso.Secret;
import com.novell.security.sso.SecretStore;

import nl.idfocus.nam.totp.TOTPException;
import nl.idfocus.nam.util.Base64;

public class EdirSecretStore implements ISecretStore 
{
	public static final String SECRET_NAME  = "\\\\IDFocus\\TOTPSecretKey";
	public static final String SCRATCH_NAME = "\\\\IDFocus\\TOTPScratchCodes";

	private LdapContext userContext;

	@Override
	public void init(Properties prop) 
	{
		// Nothing to do for now
	}

	@Override
	public void writeSecretToStore(NIDPPrincipal princ, String secretValue) throws TOTPException 
	{
		Secret secret = getSecretHandle(princ, SECRET_NAME);
		try
		{
			secret.setValue(secretValue.getBytes());
		}
		catch (SSException e)
		{
			throw new TOTPException("Could not write secret key for "+princ.getUserIdentifier(), e);
		}
		finally
		{
			closeLdapHandle();
		}
	}

	@Override
	public String readSecretFromStore(NIDPPrincipal princ) throws TOTPException 
	{
		Secret secret = getSecretHandle(princ, SECRET_NAME);
		try
		{
			return new String(secret.getValue(),"UTF-8");
		}
		catch (SSException | UnsupportedEncodingException e)
		{
			throw new TOTPException("Could not read secret key for "+princ.getUserIdentifier(), e);
		}
		finally
		{
			closeLdapHandle();
		}
	}

	@Override
	public void writeScratchCodesToStore(NIDPPrincipal princ, Integer... secretValue) throws TOTPException 
	{
		Secret scratchCodes = getSecretHandle(princ, SCRATCH_NAME);
		String deflatedValue = deflateArray(secretValue);
		try
		{
			scratchCodes.setValue(deflatedValue.getBytes());
		}
		catch (SSException e)
		{
			throw new TOTPException("Could not write scratch codes for "+princ.getUserIdentifier(), e);
		}
		finally
		{
			closeLdapHandle();
		}
	}

	@Override
	public List<Integer> readScratchCodesFromStore(NIDPPrincipal princ) throws TOTPException
	{
		Secret scratchCodes = getSecretHandle(princ, SCRATCH_NAME);
		try
		{
			String deflatedValue = new String(scratchCodes.getValue(),"UTF-8");
			return inflateArray(deflatedValue);
		}
		catch (UnsupportedEncodingException | SSException e)
		{
			throw new TOTPException("Could not read scratch codes for "+princ.getUserIdentifier(), e);
		}
		finally
		{
			closeLdapHandle();
		}
	}

	private Secret getSecretHandle(NIDPPrincipal princ, String secretName) throws TOTPException
	{
		userContext = getLdapHandleForPrincipal(princ.getAuthority(), princ.getUserIdentifier());
		SecretStore store = getSecretStoreForUser(princ.getUserIdentifier(), userContext);
		return store.getSecret(secretName);
	}

	private LdapContext getLdapHandleForPrincipal(UserAuthority authority, String userDn) throws TOTPException
	{
		try
		{
			LDAPUserAuthority lua = (LDAPUserAuthority)authority;
			JNDIUserStoreReplica rep = lua.getStore().getUserStoreReplicas()[0];
			JNDIUserStoreReplicaConnection conn = rep.getAdminConnection();
			LdapContext localCtx = (LdapContext)conn.getDirContext();
			return (LdapContext)localCtx.lookup(userDn);
		}
		catch (Exception e)
		{
			throw new TOTPException("Could not create LDAP handle for "+userDn, e);
		}
	}

	private void closeLdapHandle()
	{
		if(userContext != null)
		{
			try
			{
				userContext.close();
			}
			catch (NamingException e)
			{
				// Noop
			}
			finally
			{
				userContext = null;				
			}
		}
	}

	private SecretStore getSecretStoreForUser(String userDn, LdapContext userHandle) throws TOTPException
	{
        Hashtable<String,Object> ssEnvironment = new Hashtable<>();
        ssEnvironment.put(SecretStore.SECRET_STORE, "com.novell.security.sso.ldap.jndi.JNDISecretStore");
        ssEnvironment.put(SecretStore.HANDLE, userHandle);
        ssEnvironment.put(SecretStore.TARGET_DN, userDn);
        // Connect
        try
		{
			return SecretStore.getInstance(ssEnvironment);
		}
		catch (ClassNotFoundException | IllegalArgumentException | SSException e)
		{
			throw new TOTPException("Could not access SecretStore for "+userDn, e);
		}
	}

	private String deflateArray(Integer[] value) throws TOTPException
	{
	    ByteArrayOutputStream out = new ByteArrayOutputStream();
	    try
	    {
	    	new ObjectOutputStream(out).writeObject(value);
	    }
	    catch (IOException e)
	    {
	    	throw new TOTPException("Could not serialize integer value list", e);
	    }
	    return Base64.encodeToString(out.toByteArray(),false);
	}

	private List<Integer> inflateArray(String value) throws TOTPException
	{
	    ByteArrayInputStream in = new ByteArrayInputStream(Base64.decode(value.getBytes()));
		try
		{
			Integer[] original = (Integer[]) new ObjectInputStream(in).readObject();
		    return Arrays.asList(original);
		}
		catch (ClassNotFoundException | IOException e)
		{
	    	throw new TOTPException("Could not deserialize integer value list", e);
		}
	}
}

package nl.idfocus.nam.totp.store;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.common.util.sharedsecret.WSCSSUtil;

import nl.idfocus.nam.totp.TOTPException;
import nl.idfocus.nam.util.Base64;

public class NIDPStore implements ISecretStore 
{
	public static final String SECRET_NAME  = "IDFTOTPSecretKey";
	public static final String SECRET_TYPE  = "IDFTOTPSecretEntry";
	public static final String SCRATCH_NAME = "IDFTOTPScratchCodes";

	@Override
	public void init(Properties prop) 
	{
		// Nothing to do here
	}

	@Override
	public void writeSecretToStore(NIDPPrincipal princ, String secretValue ) throws TOTPException 
	{
		boolean saved = false;
		// Locale?
		try 
		{
			saved = WSCSSUtil.writeSecret( SECRET_NAME, new String[]{ SECRET_TYPE }, new String[] { secretValue }, princ, Locale.getDefault() );
		}
		catch (Exception e)
		{
			throw new TOTPException("Exception writing "+SECRET_NAME+" to NIDP store.",e);
		}
		if( !saved )
		{
			throw new TOTPException("failed to save secret "+SECRET_NAME);
		}
	}

	@Override
	public String readSecretFromStore(NIDPPrincipal princ) throws TOTPException 
	{
		try
		{
			return WSCSSUtil.readSSecretValue(SECRET_NAME, SECRET_TYPE, princ);
		}
		catch (Exception e)
		{
			throw new TOTPException("Failed to read secret key from NIDP store.", e);
		}
	}

	@Override
	public void writeScratchCodesToStore(NIDPPrincipal princ, Integer... secretValues) throws TOTPException 
	{
		String secretValue = deflateArray(secretValues);
		boolean saved = false;
		// Locale?
		try 
		{
			saved = WSCSSUtil.writeSecret( SCRATCH_NAME, new String[]{ SECRET_TYPE }, new String[] { secretValue }, princ, Locale.getDefault() );
		}
		catch (Exception e)
		{
			throw new TOTPException("Exception writing "+SCRATCH_NAME+" to NIDP store.",e);
		}
		if( !saved )
		{
			throw new TOTPException("failed to save secret "+SCRATCH_NAME);
		}
	}

	@Override
	public List<Integer> readScratchCodesFromStore(NIDPPrincipal princ) throws TOTPException
	{
		try
		{
			String rawValue = WSCSSUtil.readSSecretValue(SCRATCH_NAME, SECRET_TYPE, princ);
			return inflateArray(rawValue);
		}
		catch (Exception e)
		{
			throw new TOTPException("Failed to read secret key from NIDP store.", e);
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

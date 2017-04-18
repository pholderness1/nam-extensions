package nl.idfocus.nam.totp;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import nl.idfocus.nam.totp.store.NIDPStore;
import nl.idfocus.nam.totp.store.PwmStore;
import nl.idfocus.nam.totp.store.EdirSecretStore;
import nl.idfocus.nam.totp.store.ISecretStore;
import nl.idfocus.nam.totp.store.LdapStore;
import nl.idfocus.nam.util.Base32;
import nl.idfocus.nam.util.Base32.DecodingException;
import nl.idfocus.nam.util.LogFormatter;

import com.novell.nidp.NIDPPrincipal;

public class Authenticator 
{
	private static final Logger logger   = LogFormatter.getConsoleLogger( Authenticator.class.getName() );
	private              Level  dbglevel = Level.FINE;
	private static final Level  loglevel = Level.INFO;
	private static final Level  errlevel = Level.SEVERE;

	private NIDPPrincipal princ;
	private ISecretStore secretStore;
	private int windowSize;  // default 3 - max 17 (from google docs)
	private String secretKey;
	private List<Integer> scratchCodes;

	private Authenticator( Properties props ) throws TOTPException
	{
		logger.log(loglevel, "Initializing");
		windowSize = Integer.parseInt( props.getProperty( TOTPConstants.PARAM_WINDOW_SIZE, "3") );
		secretStore = initializeSecretStore(props);
		logger.log(loglevel, "done.");
	}

	private ISecretStore initializeSecretStore(Properties props) throws TOTPException
	{
		ISecretStore store;
		String storeType = props.getProperty( TOTPConstants.PARAM_STORE_TYPE, TOTPConstants.STORE_NIDP );
		if ( storeType.equals(TOTPConstants.STORE_EDIR) )
			store = new EdirSecretStore();
		else if ( storeType.equals(TOTPConstants.STORE_LDAP))
			store = new LdapStore();
		else if ( storeType.equals(TOTPConstants.STORE_PWM))
			store = new PwmStore();
		else
			store = new NIDPStore();
		store.init(props);
		return store;
	}

	public Authenticator( Properties props, UserRegistration reg ) throws TOTPException
	{
		this(props);
		setRegistration(reg);
	}

	public Authenticator( Properties props, NIDPPrincipal localPrincipal ) throws TOTPException
	{
		this(props);
		this.princ = localPrincipal;
	}

	public void setLogLevel( Level lvl )
	{
		if ( lvl != null )
			this.dbglevel = lvl;
	}

	public String getKey() throws TOTPException
	{
		logger.log(dbglevel, ">>> getKey()");
		if ( secretKey != null )
			return secretKey;
		// save key for caching
		try
		{
			secretKey = this.secretStore.readSecretFromStore(princ);
			scratchCodes = this.secretStore.readScratchCodesFromStore(princ);
			logger.log(dbglevel, "Retrieved key value and scratch codes from secretStore.");
			return secretKey;
		} catch (TOTPException e) {
			throw new TOTPException("Not registered");
		}
	}

	/**
	 * Check the code entered by the user to see if it is valid
	 * @param secret  The users secret. 
	 * @param code  The code displayed on the users device
	 * @param t  The time in msec (System.currentTimeMillis() for example)
	 * @return
	 */
	public boolean checkCode(String codeStr, long timeMsec) 
	{
		if (codeStr == null || codeStr.isEmpty())
			return false;
		logger.log(dbglevel, ">>> checkCode()");
		try
		{
			long code = Long.parseLong( codeStr );
			logger.log(dbglevel, "Token: "+code);
			byte[] decodedKey = Base32.decode( getKey() );
			
			// convert unix msec time into a 30 second "window" 
			// this is per the TOTP spec (see the RFC for details)
			long t = (timeMsec / 1000L) / 30L;
			// Window is used to check codes generated in the near past.
			// You can use this value to tune how far you're willing to go.
		
			for (int i = -windowSize; i <= windowSize; ++i) 
			{
				logger.log(dbglevel, "Window iteration "+i+"." );
				long hash = calculateCode(decodedKey, t + i);
				if (hash == code) 
				{
					logger.log(dbglevel, "Validated token." );
					return true;
				}
			}
		}
		catch (DecodingException | InvalidKeyException | NoSuchAlgorithmException | NumberFormatException | TOTPException e) {
			logger.log(dbglevel, "Could not validate code: "+e.getMessage(), e );
		} 
		// The validation code is invalid.
		logger.log(dbglevel, "Failed to validate token" );
		return false;
	}

	/**
	 * set the windows size. This is an integer value representing the number of 30 second windows we allow
	 * The bigger the window, the more tolerant of clock skew we are. 
	 * 
	 * @param s window size - must be >=1 and <=17.  Other values are ignored
	 */
	public void setWindowSize(int s) 
	{
		if( s >= 1 && s <= 17 )
			windowSize = s;
	}

	/**
	 * Calculate a TOTP code valid for the given point in time
	 * @param key the TOTP secret key bytes
	 * @param t point in time, in milliseconds
	 * @return valid TOTP code
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	private int calculateCode(byte[] key, long t) throws NoSuchAlgorithmException, InvalidKeyException 
	{
		logger.log(dbglevel, ">>> verifyCode()");
		logger.log(dbglevel, "Code: "+t);
		byte[] data = new byte[8];
		long value = t ;
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(signKey);
		byte[] hash = mac.doFinal(data);

		int offset = hash[20 - 1] & 0xF;

		// We're using a long because Java hasn't got unsigned int.
		long truncatedHash = 0;
		for (int i = 0; i < 4; ++i) {
			truncatedHash <<= 8;
			// We are dealing with signed bytes:
			// we just keep the first byte.
			truncatedHash |= (hash[offset + i] & 0xFF);
		}

		truncatedHash &= 0x7FFFFFFF;
		truncatedHash %= 1000000;

		return (int) truncatedHash;
	}

	public boolean isUserRegistered() 
	{
		try
		{
			if ( secretKey == null )
				secretKey = this.getKey();
			if ( secretKey != null )
				return true;
		} catch (TOTPException e) {
			logger.log(errlevel, "Exception checking user registration status: "+e.getMessage() );
		}
		return false;
	}

	public void setRegistration(UserRegistration reg) throws TOTPException
	{
		if ( reg != null )
		{
			this.secretKey = reg.getSecretKey();
			this.scratchCodes = reg.getScratchCodes();
		}
		else
			throw new TOTPException("Registration invalid: null");
	}

	public void persist() throws TOTPException
	{
		if( this.scratchCodes != null )
		{
			this.secretStore.writeScratchCodesToStore(princ, scratchCodes.toArray(new Integer[scratchCodes.size()]));
			logger.log(dbglevel, "Successfully saved scratch codes to secretStore." );
		}
		if ( this.secretKey != null )
		{
			this.secretStore.writeSecretToStore( princ, secretKey );
			logger.log(dbglevel, "Successfully saved key to secretStore." );
		}
		else
			throw new TOTPException("Persistence failed: secretkey null");
	}

	public boolean validateScratchCode(Integer scratchCode)
	{
		if ( scratchCodes != null )
		{
			return scratchCodes.remove(scratchCode);
		}
		return false;
	}
}

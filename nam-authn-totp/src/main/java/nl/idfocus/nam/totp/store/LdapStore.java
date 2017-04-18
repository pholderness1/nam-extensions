package nl.idfocus.nam.totp.store;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;

import com.novell.nidp.NIDPException;
import com.novell.nidp.NIDPPrincipal;
import com.novell.nidp.common.authority.UserAuthority;

import nl.idfocus.nam.totp.TOTPException;
import nl.idfocus.nam.util.Base64;

public class LdapStore implements ISecretStore
{
	public static final String	PROP_ENCRYPTION_KEY			= "EncryptionKeyValue";
	public static final String	PROP_KEY_ATTRIBUTE_NAME		= "SecretKeyAttribute";
	public static final String	PROP_SCRATCH_ATTRIBUTE_NAME	= "ScratchCodeAttribute";

	private static final String	INIT_VECTOR					= "Vot4Du7gIj9nAb6T";
	private static final String	KEY_SALT					= "6d-49Hk5";
	private String				attrNameSecretKey;
	private String				attrNameScratchCodes;
	private Cipher				encoder;
	private Cipher				decoder;

	@Override
	public void init(Properties props) throws TOTPException
	{
		attrNameSecretKey = props.getProperty(PROP_KEY_ATTRIBUTE_NAME, "l");
		attrNameScratchCodes = props.getProperty(PROP_SCRATCH_ATTRIBUTE_NAME, "description");
		String keyValue = props.getProperty(PROP_ENCRYPTION_KEY);
		initializeCiphersWithKey(keyValue);
	}

	@Override
	public void writeSecretToStore(NIDPPrincipal princ, String secretValue) throws TOTPException
	{
		String ciphertext = encodeValue(secretValue);
		UserAuthority ua = princ.getAuthority();
		try
		{
			ua.modifyAttributes(princ, new String[] { attrNameSecretKey },
					new String[] { ciphertext });
		}
		catch (NIDPException e)
		{
			throw new TOTPException(
					"failed to save secret in " + attrNameSecretKey + ": " + e.getMessage(), e);
		}
	}

	@Override
	public String readSecretFromStore(NIDPPrincipal princ) throws TOTPException
	{
		Attribute attr = readAttributeFromPrincipal(princ, attrNameSecretKey);
		try
		{
			return decodeValue((String) attr.get());
		}
		catch (NamingException | TOTPException e)
		{
			throw new TOTPException("failed to read secret key: " + e.getMessage(), e);
		}
	}

	@Override
	public void writeScratchCodesToStore(NIDPPrincipal princ, Integer... secretValue)
			throws TOTPException
	{
		List<String> result = new ArrayList<>();
		for (Integer value : secretValue)
		{
			String ciphertext = encodeValue(Integer.toString(value));
			result.add(ciphertext);
		}
		UserAuthority ua = princ.getAuthority();
		try
		{
			ua.modifyAttributes(princ, new String[] { attrNameScratchCodes },
					result.toArray(new String[result.size()]));
		}
		catch (NIDPException e)
		{
			throw new TOTPException(
					"failed to save secret in " + attrNameScratchCodes + ": " + e.getMessage(), e);
		}
	}

	@Override
	public List<Integer> readScratchCodesFromStore(NIDPPrincipal princ) throws TOTPException
	{
		Attribute attr = readAttributeFromPrincipal(princ, attrNameScratchCodes);
		List<Integer> result = new ArrayList<>();
		try
		{
			NamingEnumeration<?> values = attr.getAll();
			while (values.hasMore())
			{
				String decoded = decodeValue((String) values.next());
				result.add(Integer.parseInt(decoded));
			}
		}
		catch (NamingException | NumberFormatException | TOTPException e)
		{
			throw new TOTPException("failed to read scratch codes: " + e.getMessage(), e);
		}
		return result;
	}

	private String decodeValue(String value) throws TOTPException
	{
		try
		{
			byte[] ciphertext = Base64.decode(value);
			byte[] plaintext = decoder.doFinal(ciphertext);
			return new String(plaintext, "UTF-8");
		}
		catch (IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException e)
		{
			throw new TOTPException("Could not decipher value " + value, e);
		}
	}

	private String encodeValue(String plaintext) throws TOTPException
	{
		try
		{
			byte[] ciphertext = encoder.doFinal(plaintext.getBytes());
			return Base64.encodeToString(ciphertext, false);
		}
		catch (IllegalBlockSizeException | BadPaddingException e)
		{
			throw new TOTPException("Could not encrypt value " + plaintext, e);
		}
	}

	private Attribute readAttributeFromPrincipal(NIDPPrincipal princ, String attrName) throws TOTPException
	{
		try
		{
			UserAuthority ua = princ.getAuthority();
			Attributes attrs = ua.getAttributes(princ, new String[] { attrName });
			return attrs.get(attrName);
		}
		catch (NullPointerException e)
		{
			throw new TOTPException("Could not read principal attributes", e);
		}
	}

	private void initializeCiphersWithKey(String keyValue) throws TOTPException
	{
		try
		{
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(keyValue.toCharArray(), KEY_SALT.getBytes(), 65536, 128);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");
			byte[] ivBytes = INIT_VECTOR.getBytes("UTF-8");
			encoder = initializeCrypto(key, ivBytes, Cipher.ENCRYPT_MODE);
			decoder = initializeCrypto(key, ivBytes, Cipher.DECRYPT_MODE);
		}
		catch (UnsupportedEncodingException | InvalidKeySpecException | NoSuchAlgorithmException e)
		{
			throw new TOTPException("Could not initialize encryption key", e);
		}
	}

	private Cipher initializeCrypto(Key key, byte[] ivBytes, int mode) throws TOTPException
	{
		try
		{
			Cipher result = Cipher.getInstance("AES/CBC/PKCS5Padding");
			result.init(mode, key, new IvParameterSpec(ivBytes));
			return result;
		}
		catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException e)
		{
			throw new TOTPException("Could not initialize crypto for "
					+ (mode == Cipher.ENCRYPT_MODE ? "encryption" : "decryption"), e);
		}
	}

}

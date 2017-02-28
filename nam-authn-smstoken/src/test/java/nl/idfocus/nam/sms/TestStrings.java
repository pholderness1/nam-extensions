package nl.idfocus.nam.sms;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
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

import org.json.JSONException;
import org.json.JSONObject;

import nl.idfocus.nam.totp.TOTPException;
import nl.idfocus.nam.totp.UserRegistration;
import nl.idfocus.nam.util.Base64;

public class TestStrings
{
	private static Cipher		encoder;
//	private static Cipher		decoder;
	private static String		initVector	= "Vot4Du7gIj9nAb6T";
	private static final String	salt		= "6d-49Hk5";

	private static void initializeKey(String keyValue)
	{
		try
		{
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(keyValue.toCharArray(), salt.getBytes(), 65536, 128);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey key = new SecretKeySpec(tmp.getEncoded(), "AES");
			byte[] ivBytes = initVector.getBytes("UTF-8");
			encoder = initializeCrypto(key, ivBytes, Cipher.ENCRYPT_MODE);
//			decoder = initializeCrypto(key, ivBytes, Cipher.DECRYPT_MODE);
		}
		catch (TOTPException | UnsupportedEncodingException | InvalidKeySpecException | NoSuchAlgorithmException e)
		{
			e.printStackTrace();
		}
	}

	private static Cipher initializeCrypto(Key key, byte[] ivBytes, int mode) throws TOTPException
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

	private static String encodeValue(String plaintext) throws TOTPException
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

	private static String deflateArray(Integer[] value) throws TOTPException
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
		return Base64.encodeToString(out.toByteArray(), false);
	}

	private static List<Integer> inflateArray(String value) throws TOTPException
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

	public static String maskString(String param, int start, int end)
	{
		if (param != null && !param.isEmpty() && param.length() > (start + end))
		{
			int len = param.length() - end;
			StringBuffer res = new StringBuffer(param.substring(0, start));
			for (int i = start; i < len; i++)
				res.append("*");
			res.append(param.substring(len));
			return res.toString();
		}
		return param;
	}

	public static String createSimpleJsonObjectString(String msg, String nmbr)
	{
		String applicationId = "1234-5678-9000";
		String company = "\"rnl\"\\";
		StringBuilder json = new StringBuilder().append("{").append("\"applicationId\":")
				.append("\"").append(applicationId).append("\"").append(",")
				.append("\"operatingCompany\":").append("\"").append(company).append("\"")
				.append(",").append("\"phoneNumber\":").append("\"").append(nmbr).append("\"")
				.append(",").append("\"message\":").append("\"").append(msg).append("\"")
				.append("}");
		return json.toString();
	}

	public static String createJsonObjectString(String msg, String nmbr)
	{
		String applicationId = "1234-5678-9000";
		String company = "\"rnl\"\\";
		try
		{
			return new JSONObject().put("applicationId", applicationId)
					.put("operatingCompany", company).put("phoneNumber", nmbr).put("message", msg)
					.toString();
		}
		catch (JSONException e)
		{
			StringBuilder json = new StringBuilder().append("{").append("\"applicationId\":")
					.append("\"").append(applicationId).append("\"").append(",")
					.append("\"operatingCompany\":").append("\"").append(company).append("\"")
					.append(",").append("\"phoneNumber\":").append("\"").append(nmbr).append("\"")
					.append(",").append("\"message\":").append("\"").append(msg).append("\"")
					.append("}");
			return json.toString();
		}
	}

	private static List<String> encodeScratchCodes(List<Integer> codes) throws TOTPException
	{
		List<String> result = new ArrayList<>();
		for (Integer value : codes)
		{
			String ciphertext = encodeValue(Integer.toString(value));
			result.add(ciphertext);
		}
		return result;
	}

	public static void main(String[] args) throws Exception
	{
		System.out.println("null: " + maskString(null, 1, 4));
		System.out.println("'+31641707287': " + maskString("+31641707287", 4, 2));
		System.out.println("'06-41707287': " + maskString("06-41707287", 4, 2));
		System.out.println("---");
		System.out.println(createSimpleJsonObjectString("message", "062345678"));
		System.out.println(createJsonObjectString("message", "062345678"));
		System.out.println("---");
		Integer[] sample = new Integer[] { 10000000, 20000000, 30000000, 40000000, 50000000 };
		System.out.println(Arrays.toString(sample));
		long start = System.currentTimeMillis();
		String deflated = deflateArray(sample);
		long half = System.currentTimeMillis();
		List<Integer> inflated = inflateArray(deflated);
		long end = System.currentTimeMillis();
		System.out.println(deflated);
		System.out.println("Took " + (half - start) + " millis");
		System.out.println(inflated);
		System.out.println("Took " + (end - half) + " millis");
		System.out.println(sample[1]);
		System.out.println(inflated.get(1));
		System.out.println("---");
		UserRegistration reg = new UserRegistration(new Properties());
		System.out.println(reg.getSecretKey());
		System.out.println(reg.getScratchCodes());
		initializeKey("mijnsleutel");
		System.out.println(encodeValue(reg.getSecretKey()));
		System.out.println(encodeScratchCodes(reg.getScratchCodes()));
	}
}

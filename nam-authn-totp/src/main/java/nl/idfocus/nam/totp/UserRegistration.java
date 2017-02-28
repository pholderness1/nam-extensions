package nl.idfocus.nam.totp;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

import javax.imageio.ImageIO;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;

import nl.idfocus.nam.util.Base32;
import nl.idfocus.nam.util.Base64;

public class UserRegistration implements Serializable
{
	/**
	 * 
	 */
	private static final long serialVersionUID = -5088827110450602283L;

	private static final int SCRATCH_CODE_INVALID = -1;

	private final int secretSize;
	private final int numOfScratchCodes;
	private final int scratchCodeSize;
	private final int scratchCodeModulus;
	private final TOTPKeyMaterial secretKey;
	private String orgName;
	private String userName;
	private int imgSize;

	public UserRegistration( Properties props ) 
	{
		secretSize         = Integer.parseInt( props.getProperty( TOTPConstants.PARAM_KEY_SIZE,    "10") );
		numOfScratchCodes  = Integer.parseInt( props.getProperty( TOTPConstants.PARAM_SCRATCH,      "5") );
		scratchCodeSize    = Integer.parseInt( props.getProperty( TOTPConstants.PARAM_SCRATCH_SIZE, "8") );
		scratchCodeModulus = (int) Math.pow(10, scratchCodeSize);
		imgSize            = Integer.parseInt( props.getProperty( TOTPConstants.PARAM_IMAGE_SIZE, "200") );
		orgName            = props.getProperty( TOTPConstants.PARAM_ISSUER_NAME, "IDFocus");
		secretKey 		   = generateSecretKey();
	}

	public String getSecretKey() 
	{
		return secretKey.getKey();
	}

	public List<Integer> getScratchCodes() 
	{
		return secretKey.getScratchCodes();
	}

	public String getOrgName() 
	{
		return orgName;
	}

	public void setOrgName(String orgName) 
	{
		this.orgName = orgName;
	}

	public String getUserName()
	{
		return userName;
	}

	public void setUserName(String userName) 
	{
		this.userName = userName;
	}

	public int getImgSize() {
		return imgSize;
	}

	public void setImgSize(int imgSize) {
		this.imgSize = imgSize;
	}

	/**
	 * Generate the URI string for registration of a new user secret. <br/>
	 * This URL must be embedded in a QR code image which can be scanned. 
	 * @see https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	 * @param userName the username to be added
	 * @param key the secret key
	 * @return secret key URI string
	 */
	private String generateOtpURI()
	{
		String org = orgName;
		String usr = userName;
		try 
		{
			org = URLEncoder.encode( orgName, "UTF-8" );
			usr = URLEncoder.encode( userName, "UTF-8" );
		} 
		catch (UnsupportedEncodingException e) 
		{
			throw new IllegalStateException(e);
		}
		StringBuilder urlStr = new StringBuilder("otpauth://totp/")
			.append( org.replaceAll("\\+", "%20") )
			.append( ":" )
			.append( usr )
			.append( "?" )
			.append( "secret=" )
			.append( secretKey )
			.append( "&" )
			.append( "issuer=" )
			.append( org );
		return urlStr.toString();
	}

	/**
	 * Generate a random secret key. This must be saved by the server and associated with the 
	 * users account to verify the code displayed by Google Authenticator. 
	 * The user must register this secret on their device. 
	 * @return secret key
	 */
	private TOTPKeyMaterial generateSecretKey() 
	{
		// Allocating the buffer
		byte[] buffer = new byte[secretSize + numOfScratchCodes * scratchCodeSize];
		// Filling the buffer with random numbers.
		new SecureRandom().nextBytes(buffer);
		// Getting the key and converting it to Base32
		byte[] newSecretKey = Arrays.copyOf(buffer, secretSize);
		String keyStr = Base32.encode(newSecretKey);
		// Generate the list of scratchCodes
		List<Integer> scratchCodes = calculateScratchCodes(buffer);
		// TODO Calculate the primer code to test activation at time = 0
		int primerCode = -1;
		//
		return new TOTPKeyMaterial(keyStr, scratchCodes, primerCode);
	}

    private List<Integer> calculateScratchCodes(byte[] buffer)
    {
        List<Integer> scratchCodes = new ArrayList<>();
        while (scratchCodes.size() < numOfScratchCodes)
        {
            byte[] scratchCodeBuffer = Arrays.copyOfRange(
                    buffer,
                    secretSize + scratchCodeSize * scratchCodes.size(),
                    secretSize + scratchCodeSize * scratchCodes.size() + scratchCodeSize);

            int scratchCode = calculateScratchCode(scratchCodeBuffer);

            if (scratchCode != SCRATCH_CODE_INVALID)
            {
                scratchCodes.add(scratchCode);
            }
            else
            {
                scratchCodes.add(generateScratchCode());
            }
        }
        return scratchCodes;
    }

    /**
     * This method calculates a scratch code from a random byte buffer of
     * suitable size <code>#BYTES_PER_SCRATCH_CODE</code>.
     *
     * @param scratchCodeBuffer a random byte buffer whose minimum size is
     *                          <code>#BYTES_PER_SCRATCH_CODE</code>.
     * @return the scratch code.
     */
    private int calculateScratchCode(byte[] scratchCodeBuffer)
    {
        if (scratchCodeBuffer.length < scratchCodeSize)
        {
            throw new IllegalArgumentException(
                    String.format(
                            "The provided random byte buffer is too small: %d.",
                            scratchCodeBuffer.length));
        }
        int scratchCode = 0;

        for (int i = 0; i < scratchCodeSize; ++i)
        {
            scratchCode = (scratchCode << 8) + (scratchCodeBuffer[i] & 0xff);
        }
        scratchCode = (scratchCode & 0x7FFFFFFF) % scratchCodeModulus;
        // Accept the scratch code only if it has exactly digits.
        if (validateScratchCode(scratchCode))
        {
            return scratchCode;
        }
        else
        {
            return SCRATCH_CODE_INVALID;
        }
    }

    boolean validateScratchCode(int scratchCode)
    {
        return scratchCode >= scratchCodeModulus / 10;
    }

    /**
     * This method creates a new random byte buffer from which a new scratch
     * code is generated. This function is invoked if a scratch code generated
     * from the main buffer is invalid because it does not satisfy the scratch
     * code restrictions.
     *
     * @return A valid scratch code.
     */
    private int generateScratchCode()
    {
        while (true)
        {
            byte[] scratchCodeBuffer = new byte[scratchCodeSize];
            new SecureRandom().nextBytes(scratchCodeBuffer);

            int scratchCode = calculateScratchCode(scratchCodeBuffer);

            if (scratchCode != SCRATCH_CODE_INVALID)
            {
                return scratchCode;
            }
        }
    }

	/**
	 * Return a base64-encoded image byte array for use as &lt;img> tag contents.<br/>
	 * @see http://stackoverflow.com/questions/22878562/unable-to-display-all-info-from-the-database-through-jsp/22879097#22879097
	 * @param img
	 * @return
	 * @throws TOTPException 
	 */
	public String getQRImageString() throws TOTPException
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			ImageIO.write( generateQRImage( generateOtpURI() ), "jpg", baos );
			baos.flush();
			byte[] imageInByteArray = baos.toByteArray();
			baos.close();
			return Base64.encodeToString(imageInByteArray, false);
		} catch (IOException e) {
			throw new TOTPException("failed to write image stream: "+e.getMessage() , e);
		}
	}

    private BufferedImage generateQRImage( String text ) throws TOTPException
    {
        // Create the ByteMatrix for the QR-Code that encodes the given String
        Hashtable<EncodeHintType,Object> hintMap = new Hashtable<>();
        hintMap.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L);

        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix byteMatrix = new BitMatrix(imgSize);
		try {
			byteMatrix = qrCodeWriter.encode( text, BarcodeFormat.QR_CODE, imgSize, imgSize, hintMap );
		} catch (WriterException e) {
			throw new TOTPException("failed to encode QR image: "+e.getMessage(), e);
		}
        // Make the BufferedImage showing the QR code
        int matrixWidth = byteMatrix.getWidth();
        BufferedImage image = new BufferedImage(matrixWidth, matrixWidth,
                BufferedImage.TYPE_INT_RGB);
        image.createGraphics();

        Graphics2D graphics = (Graphics2D) image.getGraphics();
        graphics.setColor(Color.WHITE);
        graphics.fillRect(0, 0, matrixWidth, matrixWidth);
        // Paint and save the image using the ByteMatrix
        graphics.setColor(Color.BLACK);
 
        for (int i = 0; i < matrixWidth; i++) {
            for (int j = 0; j < matrixWidth; j++) {
                if (byteMatrix.get(i, j)) {
                    graphics.fillRect(i, j, 1, 1);
                }
            }
        }
        return image;
    }

}

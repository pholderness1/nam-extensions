package nl.idfocus.nam.totp;

import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.Properties;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.novell.nidp.NIDPPrincipal;

import nl.idfocus.nam.totp.store.ISecretStore;
import nl.idfocus.nam.totp.store.PwmStore;
import nl.idfocus.nam.util.MockNIDP;

public class TestPwmStore
{

	private Properties props;

	@Before
	public void setUp() throws Exception 
	{
		props = new Properties();
		props.setProperty(PwmStore.PROP_STORAGE_ATTRIBUTE_NAME, "totpSecretValuePam");
		props.setProperty(PwmStore.PROP_STORAGE_FORMAT_NAME, "PAM");
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testPwmStoreInit() throws Exception
	{
		ISecretStore store = new PwmStore();
		store.init( props );
	}

	@Test
	public void testPwmStoreReadCodes() throws Exception
	{
		/*
		 * Codes: [78636072, 81915571, 52984984, 34278800, 88440605]
		 */
		ISecretStore store = new PwmStore();
		store.init( props );
		NIDPPrincipal princ = MockNIDP.getPrincipal();
		List<Integer> codes = store.readScratchCodesFromStore(princ);
		assertEquals(5, codes.size());
		assertEquals(new Integer(78636072), codes.get(0));
		assertEquals(new Integer(81915571), codes.get(1));
		assertEquals(new Integer(52984984), codes.get(2));
		assertEquals(new Integer(34278800), codes.get(3));
		assertEquals(new Integer(88440605), codes.get(4));
	}

	@Test
	public void testPwmStoreReadKey() throws Exception
	{
		/*
		 * Key: TTLRB6ULNFYBTUZB
		 */
		ISecretStore store = new PwmStore();
		store.init( props );
		NIDPPrincipal princ = MockNIDP.getPrincipal();
		assertEquals("TTLRB6ULNFYBTUZB", store.readSecretFromStore(princ));
	}

	@Test
	public void testPwmStoreWriteCodes() throws Exception
	{
		Integer[] codes = new Integer[] { 78636072, 81915571, 52984984, 34278800, 88440605 };
		/*
		 * Codes: [78636072, 81915571, 52984984, 34278800, 88440605]
		 */
		ISecretStore store = new PwmStore();
		store.init( props );
		NIDPPrincipal princ = MockNIDP.getPrincipal();
		assertEquals(5, codes.length);
		store.writeScratchCodesToStore(princ, codes);
	}

	@Test
	public void testPwmStoreWriteKey() throws Exception
	{
		/*
		 * Key: TTLRB6ULNFYBTUZB
		 */
		ISecretStore store = new PwmStore();
		store.init( props );
		NIDPPrincipal princ = MockNIDP.getPrincipal();
		store.writeSecretToStore(princ, "TTLRB6ULNFYBTUZB");
	}
}

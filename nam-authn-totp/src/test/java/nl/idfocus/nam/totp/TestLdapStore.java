package nl.idfocus.nam.totp;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Properties;

import nl.idfocus.nam.totp.TOTPException;
import nl.idfocus.nam.totp.store.ISecretStore;
import nl.idfocus.nam.totp.store.LdapStore;
import nl.idfocus.nam.util.MockNIDP;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.novell.nidp.NIDPPrincipal;

public class TestLdapStore 
{

	/**
	 * Do NOT change as data encrypted with this key is embedded in the {@link MockNIDP#getPrincipal()} method.
	 */
	private static final String ENCRYPTIONKEY = "mijnsleutel";
	private Properties props;

	@Before
	public void setUp() throws Exception 
	{
		props = new Properties();
		props.setProperty(LdapStore.PROP_ENCRYPTION_KEY, ENCRYPTIONKEY);
		props.setProperty(LdapStore.PROP_KEY_ATTRIBUTE_NAME, "totpSecretKey");
		props.setProperty(LdapStore.PROP_SCRATCH_ATTRIBUTE_NAME, "totpScratchCodes");
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testLdapStoreInit() throws Exception
	{
		ISecretStore store = new LdapStore();
		store.init( props );
	}

	@Test
	public void testLdapStoreReadCodes() throws Exception
	{
		/*
		 * Codes: [78636072, 81915571, 52984984, 34278800, 88440605]
		 */
		ISecretStore store = new LdapStore();
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
	public void testLdapStoreWriteCodes() throws Exception
	{
		/*
		 * Codes: [78636072, 81915571, 52984984, 34278800, 88440605]
		 */
		Integer[] codes = new Integer[] { 78636072, 81915571, 52984984, 34278800, 88440605 };
		ISecretStore store = new LdapStore();
		store.init( props );
		NIDPPrincipal princ = MockNIDP.getPrincipal();
		store.writeScratchCodesToStore(princ, codes);
	}

	@Test
	public void testLdapStoreReadKey() throws Exception
	{
		/*
		 * Key: TTLRB6ULNFYBTUZB
		 */
		ISecretStore store = new LdapStore();
		store.init( props );
		NIDPPrincipal princ = MockNIDP.getPrincipal();
		assertEquals("TTLRB6ULNFYBTUZB", store.readSecretFromStore(princ));
	}

	@Test
	public void testLdapStoreReadKeyFail() throws Exception
	{
		props.setProperty(LdapStore.PROP_ENCRYPTION_KEY, "anderesleutel");
		ISecretStore store = new LdapStore();
		store.init( props );
		NIDPPrincipal princ = MockNIDP.getPrincipal();
		try
		{
			store.readSecretFromStore(princ);
			fail("Expected exception during decryption");
		}
		catch (TOTPException e)
		{
			assertTrue(e.getMessage().startsWith("failed to read"));
		}
	}

	@Test
	public void testLdapStoreWriteKey() throws Exception
	{
		/*
		 * Key: TTLRB6ULNFYBTUZB
		 */
		String key = "TTLRB6ULNFYBTUZB";
		ISecretStore store = new LdapStore();
		store.init( props );
		NIDPPrincipal princ = MockNIDP.getPrincipal();
		store.writeSecretToStore(princ, key);
	}
}

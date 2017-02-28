package nl.idfocus.nam.totp.store;

import java.util.List;
import java.util.Properties;

import com.novell.nidp.NIDPPrincipal;

import nl.idfocus.nam.totp.TOTPException;

public interface ISecretStore
{

	public void init(Properties props) throws TOTPException;

	public void writeSecretToStore(NIDPPrincipal princ, String secretValue) throws TOTPException;

	public String readSecretFromStore(NIDPPrincipal princ) throws TOTPException;

	public void writeScratchCodesToStore(NIDPPrincipal princ, Integer... secretValue) throws TOTPException;

	public List<Integer> readScratchCodesFromStore(NIDPPrincipal princ) throws TOTPException;

}

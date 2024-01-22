package com.saviynt.ssm.custom.cyberarkvault;

/**
 *
 * @author marcozhang
 */
public class VaultAuthRequestBuilder {
    public VaultAuthRequest buildAuthRequest(String username, String password)
	{
		VaultAuthRequest authReq = new VaultAuthRequest();
		authReq.setUsername(username);
		authReq.setPassword(password);
		authReq.setConcurrentSession("false");
		authReq.setSecureMode(false);
		return authReq;
		
	}
	
	public VaultAuthRequest buildAuthRequest(String username, String password, String concurrentsession)
	{
		VaultAuthRequest authReq = new VaultAuthRequest();
		authReq.setUsername(username);
		authReq.setPassword(password);
		authReq.setConcurrentSession(concurrentsession);
		authReq.setSecureMode(false);
		return authReq;
		
	}
	
	public VaultAuthRequest buildAuthRequest(String username, String password, String concurrentsession, Boolean securemode)
	{
		VaultAuthRequest authReq = new VaultAuthRequest();
		authReq.setUsername(username);
		authReq.setPassword(password);
		authReq.setConcurrentSession(concurrentsession);
		authReq.setSecureMode(securemode);
		return authReq;
		
	}
}

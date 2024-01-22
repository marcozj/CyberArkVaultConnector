package com.saviynt.ssm.custom.cyberarkvault;

/**
 *
 * @author marcozhang
 */
public class VaultAuthRequest {
    private String username;
	private String password;
	private String concurrentSession;
	private Boolean secureMode;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public Boolean getSecureMode() {
		return secureMode;
	}

	public void setSecureMode(Boolean secureMode) {
		this.secureMode = secureMode;
	}

	public String getConcurrentSession() {
		return concurrentSession;
	}

	public void setConcurrentSession(String concurrentSession) {
		this.concurrentSession = concurrentSession;
	}
}

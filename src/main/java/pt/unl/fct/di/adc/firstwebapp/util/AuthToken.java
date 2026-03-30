package pt.unl.fct.di.adc.firstwebapp.util;

import java.util.UUID;

public class AuthToken {
    public static final long EXPIRATION_TIME = 1000 * 60 * 60 * 24;

    public String tokenId;
    public String username;
    public String role;
    public long issuedAt;
    public long expiresAt;
	
	public AuthToken() { }
	
	public AuthToken(String username, String role) {
        this.tokenId = UUID.randomUUID().toString();
        this.username = username;
        this.role = role;
        this.issuedAt = System.currentTimeMillis();
        this.expiresAt = this.issuedAt + EXPIRATION_TIME;
	}
	
}

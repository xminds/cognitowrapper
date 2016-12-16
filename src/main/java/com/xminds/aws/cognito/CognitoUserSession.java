package com.xminds.aws.cognito;

import com.amazonaws.SDKGlobalTime;

import java.util.Date;

public class CognitoUserSession {
    /**
     * Cognito identity token.
     */
    private CognitoIdToken idToken;

    /**
     * Cognito access token.
     */
    private CognitoAccessToken accessToken;

    /**
     * Cognito refresh token.
     */
    private CognitoRefreshToken refreshToken;

    /**
     * Constructs a new Cognito session.
     *
     * @param idToken      REQUIRED: ID Token for this session.
     * @param accessToken  REQUIRED: Access Token for this session.
     * @param refreshToken REQUIRED: Refresh Token.
     */
    public CognitoUserSession(CognitoIdToken idToken, CognitoAccessToken accessToken, CognitoRefreshToken refreshToken) {
        this.idToken = idToken;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }

    /**
     * Returns ID Token.
     *
     * @return token as a String.
     */
    public CognitoIdToken getIdToken() {
        return idToken;
    }

    /**
     * Returns Access Token.
     *
     * @return token as a String.
     */
    public CognitoAccessToken getAccessToken() {
        return accessToken;
    }

    /**
     * Returns Refresh Token.
     *
     * @return token as a String.
     */
    public CognitoRefreshToken getRefreshToken() {
        return refreshToken;
    }

    /**
     * Returns if the access and id tokens have not expired.
     *
     * @return boolean to indicate if the access and id tokens have not expired.
     */
    public boolean isValid() {
        Date currentTimeStamp = new Date();

        try {
            return (currentTimeStamp.before(idToken.getExpiration())
                    & currentTimeStamp.before(accessToken.getExpiration()));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Returns true if this session for the threshold set in {@link CognitoIdentityProviderClientConfig#refreshThreshold}.
     *
     * @return boolean to indicate if the session is valid for atleast {@link CognitoIdentityProviderClientConfig#refreshThreshold} seconds.
     */
    public boolean isValidForThreshold() {
        try {
            long currentTime = System.currentTimeMillis() - SDKGlobalTime.getGlobalTimeOffset() * 1000;
            long expiresInMilliSeconds = idToken.getExpiration().getTime() - currentTime;
            return (expiresInMilliSeconds > CognitoIdentityProviderClientConfig.getRefreshThreshold());
        } catch (Exception e) {
            return false;
        }
    }
}
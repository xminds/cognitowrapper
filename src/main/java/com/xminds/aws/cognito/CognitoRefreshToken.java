package com.xminds.aws.cognito;

/**
 * Represents a Cognito Refresh token.
 */
public class CognitoRefreshToken extends CognitoUserToken {

    // Constructs a Cognito refresh token.
    public CognitoRefreshToken(String token) {
        super(token);
    }

    /**
     * Returns this Cognito refresh token as a String.
     *
     * @return refresh token as a string.
     */
    public String getToken() {
        return super.getToken();
    }
}

package com.xminds.aws.cognito;

/**
 * Base class for Cognito tokens.
 */
public class CognitoUserToken {
    // A Cognito Token - can be an Access, Id or Refresh token
    private String token;

    // Construct a new Cognito token
    public CognitoUserToken(String token) {
        this.token = token;
    }

    protected String getToken() {
        return token;
    }

}

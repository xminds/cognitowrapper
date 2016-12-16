package com.xminds.aws.cognito;

public class CognitoNotAuthorizedException extends CognitoIdentityProviderException {
    private static final long serialVersionUID = -4496852554085318906L;

    public CognitoNotAuthorizedException(String message, Throwable throwable) {
        super(message, throwable);
    }

    public CognitoNotAuthorizedException(String message) {
        super(message);
    }
}

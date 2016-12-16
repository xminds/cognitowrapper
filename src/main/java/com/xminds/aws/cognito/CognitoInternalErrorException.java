package com.xminds.aws.cognito;

public class CognitoInternalErrorException extends CognitoIdentityProviderException {
    private static final long serialVersionUID = 1591505124709311863L;

    public CognitoInternalErrorException(String message, Throwable throwable) {
        super(message, throwable);
    }

    public CognitoInternalErrorException(String message) {
        super(message);
    }
}

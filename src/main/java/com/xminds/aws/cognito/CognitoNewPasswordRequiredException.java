package com.xminds.aws.cognito;

/**
 * Created by vinuv on 16-12-2016.
 */
public class CognitoNewPasswordRequiredException extends CognitoIdentityProviderException {
    public CognitoNewPasswordRequiredException(String message, Throwable throwable) {
        super(message, throwable);
    }

    public CognitoNewPasswordRequiredException(String message) {
        super(message);
    }
}

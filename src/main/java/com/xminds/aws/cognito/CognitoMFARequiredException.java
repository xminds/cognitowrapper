package com.xminds.aws.cognito;

/**
 * Created by vinuv on 16-12-2016.
 */
public class CognitoMFARequiredException extends CognitoIdentityProviderException {
    public CognitoMFARequiredException(String message, Throwable throwable) {
        super(message, throwable);
    }

    public CognitoMFARequiredException(String message) {
        super(message);
    }
}

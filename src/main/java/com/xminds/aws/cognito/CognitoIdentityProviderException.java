package com.xminds.aws.cognito;

import com.amazonaws.AmazonClientException;

/**
 * This exception is thrown for any errors during Cognito Identity Provider operations
 */
public class CognitoIdentityProviderException extends AmazonClientException {

    private static final long serialVersionUID = 8038301061230088279L;

    public CognitoIdentityProviderException(String message, Throwable throwable) {
        super(message, throwable);
    }

    public CognitoIdentityProviderException(String message) {
        super(message);
    }

}
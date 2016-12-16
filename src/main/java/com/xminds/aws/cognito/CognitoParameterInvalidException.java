package com.xminds.aws.cognito;

public class CognitoParameterInvalidException extends CognitoIdentityProviderException {
    private static final long serialVersionUID = -551253513463692597L;

    public CognitoParameterInvalidException(String message, Throwable throwable) {
        super(message, throwable);
    }

    public CognitoParameterInvalidException(String message) {
        super(message);
    }
}

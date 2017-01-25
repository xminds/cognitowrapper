package com.xminds.aws.cognito;

import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeResult;

/**
 * Created by vinuv on 16-12-2016.
 */
public class CognitoNewPasswordRequiredException extends CognitoIdentityProviderException {


    private RespondToAuthChallengeResult challenge;


    public CognitoNewPasswordRequiredException(String message, RespondToAuthChallengeResult challenge) {
        super(message);
        this.challenge = challenge;
    }

    public RespondToAuthChallengeResult getChallenge() {
        return this.challenge;
    }


}

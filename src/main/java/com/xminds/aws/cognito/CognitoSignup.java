package com.xminds.aws.cognito;

/**
 * Created by vinuv on 16-12-2016.
 */
public class CognitoSignup {

    private CognitoUser user;

    private Boolean confirmed;

    private CognitoUserCodeDeliveryDetails codeDeliveryDetails;

    public CognitoSignup(CognitoUser user, Boolean confirmed, CognitoUserCodeDeliveryDetails codeDeliveryDetails) {
        this.user = user;
        this.confirmed = confirmed;
        this.codeDeliveryDetails = codeDeliveryDetails;
    }


    public CognitoUser getUser() {
        return user;
    }

    public void setUser(CognitoUser user) {
        this.user = user;
    }

    public Boolean getConfirmed() {
        return confirmed;
    }

    public void setConfirmed(Boolean confirmed) {
        this.confirmed = confirmed;
    }

    public CognitoUserCodeDeliveryDetails getCodeDeliveryDetails() {
        return codeDeliveryDetails;
    }

    public void setCodeDeliveryDetails(CognitoUserCodeDeliveryDetails codeDeliveryDetails) {
        this.codeDeliveryDetails = codeDeliveryDetails;
    }
}

package com.xminds.aws.cognito;

/**
 * Wraps user attributes {@link CognitoUserAttributes} and user settings {@link CognitoUserSettings} objects.
 */
public class CognitoUserDetails {
    private CognitoUserAttributes cognitoUserAttributes;
    private CognitoUserSettings cognitoUserSettings;

    // Constructor to create a user details wrapper
    public CognitoUserDetails(CognitoUserAttributes cognitoUserAttributes,
                              CognitoUserSettings cognitoUserSettings) {
        this.cognitoUserAttributes = cognitoUserAttributes;
        this.cognitoUserSettings = cognitoUserSettings;
    }

    /**
     * Returns users' attributes.
     *
     * @return {@link CognitoUserAttributes}
     */
    public CognitoUserAttributes getAttributes() {
        return this.cognitoUserAttributes;
    }

    /**
     * Returns users' settings
     *
     * @return {@link CognitoUserSettings}
     */
    public CognitoUserSettings getSettings() {
        return this.cognitoUserSettings;
    }
}
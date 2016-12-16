package com.xminds.aws.cognito;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.*;
import com.amazonaws.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;

public class CognitoUser {

    /**
     * CIP low-level client.
     */
    private final AWSCognitoIdentityProvider cognitoIdentityProviderClient;

    /**
     * Client ID for Your Identity Pool.
     */
    private final String clientId;

    /**
     * Client secret generated for this {@code clientId}, this may be {@code null} if a secret is not
     * generated for the {@code clientId}.
     */
    private final String clientSecret;

    /**
     * userId for this user, this is mutable to allow the userId to be set during authentication.
     * This can be the username (users' unique sign-in username) or an alias (if available, such as email or phone number).
     */
    private String userId;

    /**
     * Username used for authentication process. This will be set from the results in the pre-auth API call.
     */
    private String usernameInternal;

    /**
     * Device-key of this device, if available.
     */
    private String deviceKey;

    /**
     * Reference to the {@link CognitoUserPool} to which this user belongs .
     */
    private CognitoUserPool pool;

    /**
     * Secret-Hash for this user-pool, this is mutable because userId is mutable.
     */
    private String secretHash;

    /**
     * The current session.
     */
    private CognitoUserSession cipSession;

    /**
     * Constructs a new Cognito User from a Cognito user identity pool {@link CognitoUserPool} and userId.
     *
     * @param pool         REQUIRED: Reference to {@link CognitoUserPool}, to which this user belongs.
     * @param userId       REQUIRED: userId of this user.
     * @param clientId     REQUIRED: Client-Id of the android app.
     * @param clientSecret REQUIRED: Client secret assigned for this Client-Id.
     * @param secretHash   REQUIRED: Secret-Hash, calculated for this android app.
     * @param client       REQUIRED: Low level android client.
     */
    protected CognitoUser(CognitoUserPool pool, String userId,
                          String clientId, String clientSecret, String secretHash,
                          AWSCognitoIdentityProvider client) {
        this.pool = pool;
        this.userId = userId;
        this.cognitoIdentityProviderClient = client;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.secretHash = secretHash;
        this.deviceKey = null;
        cipSession = null;
    }

    /**
     * Returns the userId of this user.
     *
     * @return userId.
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Returns the pool Id of this user.
     *
     * @return pool Id.
     */
    public String getUserPoolId() {
        return pool.getUserPoolId();
    }

    /**
     * Method low-level client for Amazon Cognito Identity Provider.
     *
     * @return
     */
    protected AWSCognitoIdentityProvider getCognitoIdentityProviderClient() {
        return cognitoIdentityProviderClient;
    }


    /**
     * Confirms user registration in current thread.
     * <p>
     * Confirming a user is required to complete the user's registration. Any other operations on a user
     * are possible only after registration confirmation.
     * <b>Note:</b> This method will perform network operations. Calling this method in
     * applications' main thread will cause Android to throw NetworkOnMainThreadException.
     * </p>
     *
     * @param confirmationCode    REQUIRED: Code sent to the phone-number or email used to register the user
     * @param forcedAliasCreation REQUIRED: This flag indicates if the confirmation should go-through in case of
     *                            parameter contentions.
     */
    public void confirmSignUp(String confirmationCode,
                              boolean forcedAliasCreation) {

        try {
            confirmSignUpInternal(confirmationCode, forcedAliasCreation);
        } catch (AmazonServiceException e) {
            throw new CognitoIdentityProviderException("Confirm signup failed", e);
        }
    }

    /**
     * Internal method to Confirm Registration.
     *
     * @param confirmationCode    REQUIRED: Code to confirm this user.
     * @param forcedAliasCreation REQUIRED: If set over-rides parameter contentions
     */
    private void confirmSignUpInternal(String confirmationCode, boolean forcedAliasCreation) {
        ConfirmSignUpRequest confirmUserRegistrationRequest = new ConfirmSignUpRequest();
        confirmUserRegistrationRequest.setClientId(clientId);
        confirmUserRegistrationRequest.setSecretHash(secretHash);
        confirmUserRegistrationRequest.setUsername(userId);
        confirmUserRegistrationRequest.setConfirmationCode(confirmationCode);
        confirmUserRegistrationRequest.setForceAliasCreation(forcedAliasCreation);

        cognitoIdentityProviderClient.confirmSignUp(confirmUserRegistrationRequest);
    }


    /**
     * Request to resend registration confirmation code for a user, in current thread.
     * <p>
     * <b>Note:</b> This method will perform network operations. Calling this method in
     * applications' main thread will cause Android to throw NetworkOnMainThreadException.
     * </p>
     */
    public CognitoUserCodeDeliveryDetails resendConfirmationCode() {

        try {
            ResendConfirmationCodeResult resendConfirmationCodeResult = resendConfirmationCodeInternal();
            return (new CognitoUserCodeDeliveryDetails(resendConfirmationCodeResult.getCodeDeliveryDetails()));
        } catch (Exception e) {
            throw new CognitoIdentityProviderException("Resend confirmation code fail", e);
        }
    }

    /**
     * Internal method to request registration code resend.
     */
    private ResendConfirmationCodeResult resendConfirmationCodeInternal() {
        ResendConfirmationCodeRequest resendConfirmationCodeRequest = new ResendConfirmationCodeRequest();
        resendConfirmationCodeRequest.setUsername(userId);
        resendConfirmationCodeRequest.setClientId(clientId);
        resendConfirmationCodeRequest.setSecretHash(secretHash);

        return cognitoIdentityProviderClient.resendConfirmationCode(resendConfirmationCodeRequest);
    }

    /**
     * Returns the delivery details for forgotpass
     *
     * @return
     */
    public CognitoUserCodeDeliveryDetails forgotPassword() {
        final CognitoUser cognitoUser = this;

        try {
            ForgotPasswordResult forgotPasswordResult = forgotPasswordInternal();
            return new CognitoUserCodeDeliveryDetails(forgotPasswordResult.getCodeDeliveryDetails());
        } catch (AmazonServiceException e) {
            throw new CognitoIdentityProviderException("Forgot pass initial failed", e);
        }
    }

    /**
     * Internal method to start forgot password process.
     */
    private ForgotPasswordResult forgotPasswordInternal() {
        ForgotPasswordRequest resetPasswordRequest = new ForgotPasswordRequest();
        resetPasswordRequest.setClientId(clientId);
        resetPasswordRequest.setSecretHash(secretHash);
        resetPasswordRequest.setUsername(userId);

        return cognitoIdentityProviderClient.forgotPassword(resetPasswordRequest);
    }

    /**
     * Sends the new password and the verification code to Cognito Identity Provider service, in background.
     *
     * @param verificationCode REQUIRED: Code sent from Cognito Identity Provider Service.
     * @param newPassword      REQUIRED: New password. On successful verification of {@code verificationCode},
     *                         this will be the new password for this user.
     */
    public void confirmPassword(final String verificationCode,
                                final String newPassword) {
        try {
            confirmPasswordInternal(verificationCode, newPassword);
        } catch (AmazonServiceException e) {
            throw new CognitoIdentityProviderException("Confirm password fail", e);
        }
    }

    /**
     * Internal method to set a new password.
     *
     * @param verificationCode REQUIRED: Verification code sent to the user.
     * @param newPassword      REQUIRED: New password for the user.
     */
    private void confirmPasswordInternal(String verificationCode, String newPassword) {
        ConfirmForgotPasswordRequest confirmResetPasswordRequest = new ConfirmForgotPasswordRequest();
        confirmResetPasswordRequest.setUsername(userId);
        confirmResetPasswordRequest.setClientId(clientId);
        confirmResetPasswordRequest.setSecretHash(secretHash);
        confirmResetPasswordRequest.setConfirmationCode(verificationCode);
        confirmResetPasswordRequest.setPassword(newPassword);

        cognitoIdentityProviderClient.confirmForgotPassword(confirmResetPasswordRequest);
    }


    /**
     * @return
     */
    public CognitoUserSession getSession() {
        try {
            getCachedSession();
            return cipSession;
        } catch (InvalidParameterException e) {
            throw e;
        } catch (CognitoNotAuthorizedException e) {
            throw e;
        } catch (Exception e) {
            throw new CognitoIdentityProviderException("Getsession fail", e);
        }
    }

    /**
     * Initiates user authentication through the generic auth flow (also called as Enhanced or Custom authentication).
     * This is the first step in user authentication. The response to this step from the service will contain
     * information about the next step in the authentication process.
     *
     * @param authenticationDetails REQUIRED: Contains details about the user authentication.
     * @return {@link CognitoUserSession} .
     */
    public CognitoUserSession initiateUserAuthentication(final AuthenticationDetails authenticationDetails) {
        if (CognitoServiceConstants.CHLG_TYPE_USER_PASSWORD_VERIFIER.equals(authenticationDetails.getAuthenticationType())) {
            return startWithUserSrpAuth(authenticationDetails);
        } else if (CognitoServiceConstants.CHLG_TYPE_CUSTOM_CHALLENGE.equals(authenticationDetails.getAuthenticationType())) {
            return startWithCustomAuth(authenticationDetails);
        } else {
            throw new CognitoParameterInvalidException("Unsupported authentication type " + authenticationDetails.getAuthenticationType());
        }
    }

    /**
     * Responds to an MFA challenge. This method creates a response to the challenge and calls the
     * internal method to respond to the authentication challenge.
     *
     * @param mfaCode   REQUIRED: The MFA code received by the user.
     * @param challenge REQUIRED: Current challenge {@link RespondToAuthChallengeResult}.
     * @return {@link CognitoUserSession} .
     */
    public CognitoUserSession respondToMfaChallenge(final String mfaCode, final RespondToAuthChallengeResult challenge) {
        final RespondToAuthChallengeRequest challengeResponse = new RespondToAuthChallengeRequest();
        Map<String, String> mfaParameters = new HashMap<String, String>();
        mfaParameters.put(CognitoServiceConstants.CHLG_RESP_SMS_MFA_CODE, mfaCode);
        mfaParameters.put(CognitoServiceConstants.CHLG_RESP_USERNAME, usernameInternal);
        mfaParameters.put(CognitoServiceConstants.CHLG_RESP_DEVICE_KEY, deviceKey);
        mfaParameters.put(CognitoServiceConstants.CHLG_RESP_SECRET_HASH, secretHash);
        challengeResponse.setClientId(clientId);
        challengeResponse.setSession(challenge.getSession());
        challengeResponse.setChallengeName(challenge.getChallengeName());
        challengeResponse.setChallengeResponses(mfaParameters);
        return respondToChallenge(challengeResponse);
    }

    /**
     * Call this method for valid, cached tokens for this user.
     *
     * @return Valid, cached tokens {@link CognitoUserSession}. {@code null} otherwise.
     */
    protected CognitoUserSession getCachedSession() {
        if (userId == null) {
            throw new CognitoNotAuthorizedException("User-ID is null");
        }

        if (cipSession != null) {
            if (cipSession.isValidForThreshold()) {
                return cipSession;
            }
        }

        CognitoUserSession cachedTokens = readCachedTokens();

        if (cachedTokens.isValidForThreshold()) {
            cipSession = cachedTokens;
            return cipSession;
        }

        if (cachedTokens.getRefreshToken() != null) {
            try {
                cipSession = refreshSession(cachedTokens);
                cacheTokens(cipSession);
                return cipSession;
            } catch (NotAuthorizedException nae) {
                clearCachedTokens();
                throw new CognitoNotAuthorizedException("User is not authenticated", nae);
            } catch (Exception e) {
                throw new CognitoInternalErrorException("Failed to authenticate user", e);
            }
        }
        throw new CognitoNotAuthorizedException("User is not authenticated");
    }

    /**
     * Request to change password for this user, in current thread.
     * <p>
     * This operation requires a valid accessToken {@link CognitoUserSession#accessToken}.
     * Unauthenticated users will need to be authenticated before calling this method.
     * <b>Note:</b> This method will perform network operations. Calling this method in
     * applications' main thread will cause Android to throw NetworkOnMainThreadException.
     * </p>
     *
     * @param oldUserPassword REQUIRED: Current password of this user.
     * @param newUserPassword REQUIRED: New password for this user.
     */
    public void changePassword(final String oldUserPassword,
                               final String newUserPassword) {

        try {
            changePasswordInternal(oldUserPassword, newUserPassword, getCachedSession());
        } catch (Exception e) {
            throw new CognitoIdentityProviderException("Changepass fail", e);
        }
    }

    /**
     * Internal method to change a user password.
     *
     * @param oldUserPassword REQUIRED: old password.
     * @param newUserPassword REQUIRED: new password.
     * @param session         REQUIRED: {@link CognitoUserSession}.
     */
    private void changePasswordInternal(String oldUserPassword, String newUserPassword,
                                        CognitoUserSession session) {
        if (session != null && session.isValid()) {
            ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest();
            changePasswordRequest.setPreviousPassword(oldUserPassword);
            changePasswordRequest.setProposedPassword(newUserPassword);
            changePasswordRequest.setAccessToken(session.getAccessToken().getJWTToken());
            cognitoIdentityProviderClient.changePassword(changePasswordRequest);
        } else {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }
    }

    /**
     * Retrieves the current user attributes. Runs on current thread.
     * <p>
     * <p>
     * All attributes, which are set for this user, are fetched.
     * This method requires valid accessToken.
     * <b>Note:</b> This method will perform network operations. Calling this method in
     * applications' main thread will cause Android to throw NetworkOnMainThreadException.
     * </p>
     */
    public CognitoUserDetails getDetails() {

        try {
            CognitoUserDetails userDetails = getUserDetailsInternal(this.getCachedSession());
            return userDetails;
        } catch (Exception e) {
            throw new CognitoIdentityProviderException("Get details fail", e);
        }
    }

    /**
     * Internal method to fetch user attributes.
     *
     * @param session REQUIRED: {@link CognitoUserSession}
     * @return User attributes
     */
    private CognitoUserDetails getUserDetailsInternal(CognitoUserSession session) {
        if (session != null && session.isValid()) {
            GetUserRequest getUserRequest = new GetUserRequest();
            getUserRequest.setAccessToken(session.getAccessToken().getJWTToken());
            GetUserResult userResult = cognitoIdentityProviderClient.getUser(getUserRequest);

            return new CognitoUserDetails(new CognitoUserAttributes(userResult.getUserAttributes()),
                    new CognitoUserSettings(userResult.getMFAOptions()));
        } else {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }
    }

    /**
     * Requests code to verify a user attribute, in current thread.
     * <p>
     * The user attributes that can be verified are those attributes that can be used to
     * communicate with the user, e.g. phone_number and email.
     * The verification code is sent to the medium that is represented by the attribute.
     * Attribute verification is required to enable the attribute to be used an attribute as alias
     * for the user.
     * Aliases attributes can be used in lieu of the userId to authenticate the user.
     * If an attribute was used in the confirm the user after sign-up, then that alias is
     * already verified and does not require re-verification.
     * <b>Note:</b> This method will perform network operations. Calling this method in
     * applications' main thread will cause Android to throw NetworkOnMainThreadException.
     * </p>
     *
     * @param attributeName REQUIRED: Name of the attribute that requires verification.
     */
    public CognitoUserCodeDeliveryDetails getAttributeVerificationCode(String attributeName) {

        try {
            GetUserAttributeVerificationCodeResult getUserAttributeVerificationCodeResult =
                    getAttributeVerificationCodeInternal(attributeName, this.getCachedSession());
            return new CognitoUserCodeDeliveryDetails(getUserAttributeVerificationCodeResult.getCodeDeliveryDetails());
        } catch (Exception e) {
            throw new CognitoIdentityProviderException("Attribute verification failed for " + attributeName, e);
        }
    }

    /**
     * Internal method to request for attribute verification code.
     *
     * @param attributeName REQUIRED: Name of the attribute that requires verification.
     * @param session       REQUIRED: A valid {@link CognitoUserSession}.
     */
    private GetUserAttributeVerificationCodeResult getAttributeVerificationCodeInternal(final String attributeName,
                                                                                        final CognitoUserSession session) {
        if (session != null && session.isValid()) {
            GetUserAttributeVerificationCodeRequest getUserAttributeVerificationCodeRequest
                    = new GetUserAttributeVerificationCodeRequest();
            getUserAttributeVerificationCodeRequest.setAccessToken(session.getAccessToken().getJWTToken());
            getUserAttributeVerificationCodeRequest.setAttributeName(attributeName);

            return cognitoIdentityProviderClient.getUserAttributeVerificationCode(getUserAttributeVerificationCodeRequest);
        } else {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }
    }


    /**
     * Verify an attribute with the verification code, in current thread.
     * <p>
     * Call this method to verify an attribute with the "verification code".
     * To request for a "verification code" call the method
     * {@link CognitoUser#getAttributeVerificationCode(String)}.
     * </p>
     *
     * @param attributeName    REQUIRED: The attribute that is being verified.
     * @param verificationCode REQUIRED: The code for verification.
     */
    public void verifyAttribute(String attributeName,
                                String verificationCode) {


        try {
            VerifyUserAttributeResult verifyUserAttributeResult =
                    verifyAttributeInternal(attributeName, verificationCode, this.getCachedSession());
        } catch (Exception e) {
            throw new CognitoIdentityProviderException("Verify attribute fail for " + attributeName);
        }
    }

    /**
     * Internal method to verify an attribute.
     *
     * @param attributeName    REQUIRED: The attribute that is being verified.
     * @param verificationCode REQUIRED: The code for verification.
     * @param session          REQUIRED: A valid {@link CognitoUserSession}.
     * @return {@link VerifyUserAttributeResult}
     */
    private VerifyUserAttributeResult verifyAttributeInternal(String attributeName,
                                                              String verificationCode,
                                                              CognitoUserSession session) {
        if (session != null && session.isValid()) {
            VerifyUserAttributeRequest verifyUserAttributeRequest = new VerifyUserAttributeRequest();
            verifyUserAttributeRequest.setAttributeName(attributeName);
            verifyUserAttributeRequest.setAccessToken(session.getAccessToken().getJWTToken());
            verifyUserAttributeRequest.setCode(verificationCode);

            return cognitoIdentityProviderClient.verifyUserAttribute(verifyUserAttributeRequest);
        } else {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }
    }


    /**
     * Updates attributes for a user. Runs in background.
     * <p>
     * Requires valid accessToken.
     * </p>
     *
     * @param attributes REQUIRED: All attributes and values that need to be updated for this  user.
     */
    public List<CognitoUserCodeDeliveryDetails> updateAttributes(final CognitoUserAttributes attributes
    ) {


        try {
            CognitoUserSession session = getCachedSession();
            UpdateUserAttributesResult updateUserAttributesResult =
                    updateAttributesInternal(attributes, session);

            List<CognitoUserCodeDeliveryDetails> attributesVerificationList =
                    new ArrayList<CognitoUserCodeDeliveryDetails>();
            if (updateUserAttributesResult.getCodeDeliveryDetailsList() != null) {
                for (CodeDeliveryDetailsType details : updateUserAttributesResult.getCodeDeliveryDetailsList()) {
                    attributesVerificationList.add(new CognitoUserCodeDeliveryDetails(details));
                }
            }
            return (attributesVerificationList);
        } catch (Exception e) {
            throw new CognitoIdentityProviderException("Update attributtes fail", e);
        }
    }

    /**
     * Helper method to update user attributes.
     *
     * @param attributes REQUIRED: Attributes.
     * @param session    REQUIRED: A valid {@link CognitoUserSession}.
     */
    private UpdateUserAttributesResult updateAttributesInternal(final CognitoUserAttributes attributes,
                                                                final CognitoUserSession session) {
        if (session != null && session.isValid()) {
            UpdateUserAttributesRequest updateUserAttributesRequest = new UpdateUserAttributesRequest();
            updateUserAttributesRequest.setAccessToken(session.getAccessToken().getJWTToken());
            updateUserAttributesRequest.setUserAttributes(attributes.getAttributesList());

            return cognitoIdentityProviderClient.updateUserAttributes(updateUserAttributesRequest);
        } else {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }
    }


    /**
     * Deletes user attributes, in current thread.
     * <p>
     * <b>Note:</b> This method will perform network operations. Calling this method in
     * applications' main thread will cause Android to throw NetworkOnMainThreadException.
     * </p>
     *
     * @param attributeNamesToDelete REQUIRED: List of user attributes that have to be deleted.
     */
    public void deleteAttributes(final List<String> attributeNamesToDelete) {

        try {
            deleteAttributesInternal(attributeNamesToDelete, this.getCachedSession());
        } catch (Exception e) {
            throw new CognitoIdentityProviderException("Delete attributes fail", e);
        }
    }

    /**
     * Internal method to delete user attributes.
     *
     * @param attributeNamesToDelete REQUIRED: Attribute that is being deleted.
     * @param session                REQUIRED: A valid {@link CognitoUserSession}.
     */
    private void deleteAttributesInternal(final List<String> attributeNamesToDelete,
                                          final CognitoUserSession session) {

        // Check if session is valid
        if (session == null) {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }

        if (!session.isValid()) {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }

        // Validate the attributes to delete list
        if (attributeNamesToDelete == null) {
            return;
        }

        if (attributeNamesToDelete.size() < 1) {
            return;
        }

        // Translating to AttributeNameType list
        DeleteUserAttributesRequest deleteUserAttributesRequest = new DeleteUserAttributesRequest();
        deleteUserAttributesRequest.setAccessToken(session.getAccessToken().getJWTToken());
        deleteUserAttributesRequest.setUserAttributeNames(attributeNamesToDelete);

        cognitoIdentityProviderClient.deleteUserAttributes(deleteUserAttributesRequest);
    }

    /**
     * Sign-Out this user by removing all cached tokens.
     */
    public void signOut() {
        cipSession = null;
        clearCachedTokens();
    }


    /**
     * Sign-out from all devices associated with this user, in current thread.
     */
    public void globalSignOut() {
        try {
            globalSignOutInternal(this.getCachedSession());
            signOut();
        } catch (Exception e) {
            throw new CognitoIdentityProviderException("Global signout fail", e);
        }
    }

    /**
     * Internal method to Sign-Out from all devices of this user.
     */
    private void globalSignOutInternal(CognitoUserSession session) {
        // Check if session is valid
        if (session == null) {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }

        if (!session.isValid()) {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }

        GlobalSignOutRequest globalSignOutRequest = new GlobalSignOutRequest();
        globalSignOutRequest.setAccessToken(getCachedSession().getAccessToken().getJWTToken());

        cognitoIdentityProviderClient.globalSignOut(globalSignOutRequest);
    }


    /**
     * Deletes this user, in current thread.
     */
    public void deleteUser() {

        try {
            deleteUserInternal(this.getCachedSession());
        } catch (Exception e) {
            throw new CognitoIdentityProviderException("Delete user failed", e);
        }
    }

    /**
     * Internal method to delete a user.
     *
     * @param session REQUIRED: A valid {@link CognitoUserSession}
     */
    private void deleteUserInternal(final CognitoUserSession session) {

        // Check if session is valid
        if (session == null) {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }

        if (!session.isValid()) {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }

        DeleteUserRequest deleteUserRequest = new DeleteUserRequest();
        deleteUserRequest.setAccessToken(session.getAccessToken().getJWTToken());

        cognitoIdentityProviderClient.deleteUser(deleteUserRequest);
    }


    /**
     * Set's user settings, in current thread.
     * <p>
     * <b>Note:</b> This method will perform network operations. Calling this method in
     * applications' main thread will cause Android to throw NetworkOnMainThreadException.
     * </p>
     *
     * @param cognitoUserSettings REQUIRED: User settings as {@link CognitoUserSettings}.
     */
    public void setUserSettings(CognitoUserSettings cognitoUserSettings) {
        try {
            setUserSettingsInternal(cognitoUserSettings, this.getCachedSession());
        } catch (Exception e) {
            throw new CognitoIdentityProviderException("Set usersetting fail", e);
        }
    }

    /**
     * Internal method to set MFA delivery options.
     *
     * @param cognitoUserSettings REQUIRED: {@link CognitoUserAttributes}, with MFA delivery options.
     * @param session             REQUIRED: A valid {@link CognitoUserSession}.
     */
    private void setUserSettingsInternal(CognitoUserSettings cognitoUserSettings,
                                         CognitoUserSession session) {
        if (session != null && session.isValid()) {
            if (cognitoUserSettings == null) {
                throw new CognitoParameterInvalidException("user attributes is null");
            }
            SetUserSettingsRequest setUserSettingsRequest = new SetUserSettingsRequest();
            setUserSettingsRequest.setAccessToken(session.getAccessToken().getJWTToken());
            setUserSettingsRequest.setMFAOptions(cognitoUserSettings.getSettingsList());

            SetUserSettingsResult setUserSettingsResult =
                    cognitoIdentityProviderClient.setUserSettings(setUserSettingsRequest);
        } else {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }
    }

    /**
     * Removes all cached tokens.
     */
    private void clearCachedTokens() {
//        try {
//            // Clear all cached tokens.
//            SharedPreferences csiCachedTokens =  context.getSharedPreferences("CognitoIdentityProviderCache", 0);
//
//            // Format "key" strings
//            String csiIdTokenKey      =  String.format("CognitoIdentityProvider.%s.%s.idToken", clientId, userId);
//            String csiAccessTokenKey  =  String.format("CognitoIdentityProvider.%s.%s.accessToken", clientId, userId);
//            String csiRefreshTokenKey =  String.format("CognitoIdentityProvider.%s.%s.refreshToken", clientId, userId);
//
//            SharedPreferences.Editor cacheEdit = csiCachedTokens.edit();
//            cacheEdit.remove(csiIdTokenKey);
//            cacheEdit.remove(csiAccessTokenKey);
//            cacheEdit.remove(csiRefreshTokenKey).apply();
//        } catch (Exception e) {
//            // Logging exception, this is not a fatal error
//            Log.e(TAG, "Error while deleting from SharedPreferences");
//        }
    }

    /**
     * Checks for any valid tokens.
     *
     * @return {@link CognitoUserSession} if cached tokens are available.
     */
    private CognitoUserSession readCachedTokens() {
        CognitoUserSession userSession = new CognitoUserSession(null, null, null);

//        try {
//            SharedPreferences csiCachedTokens = context.getSharedPreferences("CognitoIdentityProviderCache", 0);
//
//            // Format "key" strings
//            String csiIdTokenKey        = "CognitoIdentityProvider." + clientId + "." + userId + ".idToken";
//            String csiAccessTokenKey    = "CognitoIdentityProvider." + clientId + "." + userId + ".accessToken";
//            String csiRefreshTokenKey   = "CognitoIdentityProvider." + clientId + "." + userId + ".refreshToken";
//
//            if (csiCachedTokens.contains(csiIdTokenKey)) {
//                CognitoIdToken csiCachedIdToken = new CognitoIdToken(csiCachedTokens.getString(csiIdTokenKey, null));
//                CognitoAccessToken csiCachedAccessToken = new CognitoAccessToken(csiCachedTokens.getString(csiAccessTokenKey, null));
//                CognitoRefreshToken csiCachedRefreshToken = new CognitoRefreshToken(csiCachedTokens.getString(csiRefreshTokenKey, null));
//                userSession = new CognitoUserSession(csiCachedIdToken, csiCachedAccessToken, csiCachedRefreshToken);
//            }
//        } catch (Exception e) {
//            // Logging exception, this is not a fatal error
//            Log.e(TAG, "Error while reading SharedPreferences");
//        }
        return userSession;
    }

    /**
     * Cache tokens locally.
     *
     * @param session REQUIRED: Tokens to be cached.
     */
    private void cacheTokens(CognitoUserSession session) {
        this.cipSession = session;
//        try {
//            SharedPreferences csiCachedTokens = context.getSharedPreferences("CognitoIdentityProviderCache", 0);
//
//            String csiUserPoolId = pool.getUserPoolId();
//
//            // Create keys to look for cached tokens
//            String csiIdTokenKey        = "CognitoIdentityProvider." + clientId + "." + userId + ".idToken";
//            String csiAccessTokenKey    = "CognitoIdentityProvider." + clientId + "." + userId + ".accessToken";
//            String csiRefreshTokenKey   = "CognitoIdentityProvider." + clientId + "." + userId + ".refreshToken";
//            String csiLastUserKey       = "CognitoIdentityProvider." + clientId + ".LastAuthUser";
//
//            // Store the data in Shared Preferences
//            SharedPreferences.Editor cacheEdit = csiCachedTokens.edit();
//            cacheEdit.putString(csiIdTokenKey, session.getIdToken().getJWTToken());
//            cacheEdit.putString(csiAccessTokenKey, session.getAccessToken().getJWTToken());
//            cacheEdit.putString(csiRefreshTokenKey, session.getRefreshToken().getToken());
//            cacheEdit.putString(csiLastUserKey, userId).apply();
//
//        } catch (Exception e) {
//            // Logging exception, this is not a fatal error
//            Log.e(TAG, "Error while writing to SharedPreferences.");
//        }
    }

    /**
     * Creates a user session with the tokens from authentication.
     *
     * @param authResult REQUIRED: Authentication result which contains the
     *                   tokens.
     * @return {@link CognitoUserSession} with the latest tokens.
     */
    private CognitoUserSession getCognitoUserSession(AuthenticationResultType authResult) {
        return getCognitoUserSession(authResult, null);
    }

    /**
     * Creates a user session with the tokens from authentication and overrider the refresh token
     * with the value passed.
     *
     * @param authResult           REQUIRED: Authentication result which contains the
     *                             tokens.
     * @param refreshTokenOverride REQUIRED: This will be used to create a new session
     *                             object if it is not null.
     * @return {@link CognitoUserSession} with the latest tokens.
     */
    private CognitoUserSession getCognitoUserSession(AuthenticationResultType authResult,
                                                     CognitoRefreshToken refreshTokenOverride) {
        String idtoken = authResult.getIdToken();
        CognitoIdToken idToken = new CognitoIdToken(idtoken);

        String acctoken = authResult.getAccessToken();
        CognitoAccessToken accessToken = new CognitoAccessToken(acctoken);

        CognitoRefreshToken refreshToken;

        if (refreshTokenOverride != null) {
            refreshToken = refreshTokenOverride;
        } else {
            String reftoken = authResult.getRefreshToken();
            refreshToken = new CognitoRefreshToken(reftoken);
        }
        return new CognitoUserSession(idToken, accessToken, refreshToken);
    }

    /**
     * Internal method to refresh current {@link CognitoUserSession}, is a refresh token is available.
     *
     * @param currSession REQUIRED: Current cached {@link CognitoUserSession}.
     * @return {@link CognitoUserSession} with new access and id tokens.
     */
    private CognitoUserSession refreshSession(CognitoUserSession currSession) {
        CognitoUserSession cognitoUserSession = null;
        InitiateAuthRequest initiateAuthRequest = initiateRefreshTokenAuthRequest(currSession);
        InitiateAuthResult refreshSessionResult = cognitoIdentityProviderClient.initiateAuth(initiateAuthRequest);
        if (refreshSessionResult.getAuthenticationResult() == null) {
            throw new CognitoNotAuthorizedException("user is not authenticated");
        }
        cognitoUserSession = getCognitoUserSession(refreshSessionResult.getAuthenticationResult(), currSession.getRefreshToken());
        return cognitoUserSession;
    }

    /**
     * This method sends the challenge response to the Cognito IDP service. The call to the Cognito IDP
     * service returns a new challenge and a different method is called to process the challenge.
     * Restarts authentication if the service cannot find a device-key.
     *
     * @param challengeResponse REQUIRED: {@link RespondToAuthChallengeRequest} contains
     *                          response for the current challenge.
     * @return {@link Runnable} for the next step in user authentication.
     */
    public CognitoUserSession respondToChallenge(final RespondToAuthChallengeRequest challengeResponse) {
        try {
            if (challengeResponse != null && challengeResponse.getChallengeResponses() != null) {
                Map<String, String> challengeResponses = challengeResponse.getChallengeResponses();
                challengeResponses.put(CognitoServiceConstants.CHLG_RESP_DEVICE_KEY, deviceKey);
                challengeResponse.setChallengeResponses(challengeResponses);
            }
            RespondToAuthChallengeResult challenge = cognitoIdentityProviderClient.respondToAuthChallenge(challengeResponse);
            return handleChallenge(challenge);
        } catch (final ResourceNotFoundException rna) {
            final CognitoUser cognitoUser = this;
            if (rna.getMessage().contains("Device")) {
                //CognitoDeviceHelper.clearCachedDevice(usernameInternal, pool.getUserPoolId(), context);
                throw rna;
            } else {
                throw rna;
            }
        } catch (final Exception e) {
            throw new CognitoIdentityProviderException("Respond to challenge", e);
        }
    }

    /**
     * This method starts the user authentication with user password verification.
     * Restarts authentication if the service cannot find a device-key.
     *
     * @param authenticationDetails REQUIRED: {@link AuthenticationDetails} contains user details
     *                              for authentication.
     * @return {@link CognitoUserSession} if found
     */
    private CognitoUserSession startWithUserSrpAuth(final AuthenticationDetails authenticationDetails) {
        AuthenticationHelper authenticationHelper = new AuthenticationHelper(pool.getUserPoolId());
        InitiateAuthRequest initiateAuthRequest = initiateUserSrpAuthRequest(authenticationDetails, authenticationHelper);
        try {
            InitiateAuthResult initiateAuthResult = cognitoIdentityProviderClient.initiateAuth(initiateAuthRequest);
            updateInternalUsername(initiateAuthResult.getChallengeParameters());
            if (CognitoServiceConstants.CHLG_TYPE_USER_PASSWORD_VERIFIER.equals(initiateAuthResult.getChallengeName())) {
                if (authenticationDetails.getPassword() != null) {
                    RespondToAuthChallengeRequest challengeRequest = userSrpAuthRequest(initiateAuthResult, authenticationDetails, authenticationHelper);
                    return respondToChallenge(challengeRequest);
                }
            }
            return handleChallenge(initiateAuthResult);
        } catch (final ResourceNotFoundException rna) {
            final CognitoUser cognitoUser = this;
            if (rna.getMessage().contains("Device")) {
                // CognitoDeviceHelper.clearCachedDevice(usernameInternal, pool.getUserPoolId(), context);
                throw rna;
            } else {
                throw rna;
            }
        } catch (final Exception e) {
            throw new CognitoIdentityProviderException("startWithUserSrpAuth", e);
        }
    }

    /**
     * This method starts the user authentication with a custom (developer defined) flow.
     *
     * @param authenticationDetails REQUIRED: {@link AuthenticationDetails} contains details
     *                              about the custom authentication flow.
     * @return {@link CognitoUserSession} if found
     */
    private CognitoUserSession startWithCustomAuth(final AuthenticationDetails authenticationDetails) {
        InitiateAuthRequest initiateAuthRequest = initiateCustomAuthRequest(authenticationDetails);
        try {
            InitiateAuthResult initiateAuthResult = cognitoIdentityProviderClient.initiateAuth(initiateAuthRequest);
            return handleChallenge(initiateAuthResult);
        } catch (final Exception e) {
            throw new CognitoIdentityProviderException("startWithCustomAuth", e);
        }
    }

    /**
     * Find the next step from the challenge.
     * This is an important step in the generic authentication flow. After the responding to a challenge,
     * the results are analyzed here to determine the next step in the authentication process.
     * Like all other methods in this SDK, this is designed to work with Continuation objects.
     * This method returns a {@link Runnable} with the code to be executed, for the next step, to the invoking Continuation.
     * The possible steps are
     * 1) Authentication was successful and we have the tokens, in this case we call {@code onSuccess()} to return the tokens.
     * 2) User password is required, an AuthenticationContinuation is created.
     * 3) MFA validation is required, a MultiFactorAuthenticationContinuation object is created.
     * 4) Other generic challenge, the challenge details are passed to the user.
     *
     * @param challenge REQUIRED: Current challenge details, {@link RespondToAuthChallengeResult}.
     * @return {@link CognitoUserSession} for the next step in user authentication.
     */
    private CognitoUserSession handleChallenge(final RespondToAuthChallengeResult challenge) {
        final CognitoUser cognitoUser = this;

        if (challenge == null) {
            throw new CognitoInternalErrorException("Authentication failed due to an internal error");
        }

        updateInternalUsername(challenge.getChallengeParameters());
        String challengeName = challenge.getChallengeName();
        if (challengeName == null) {
            final CognitoUserSession cognitoUserSession = getCognitoUserSession(challenge.getAuthenticationResult());
            cacheTokens(cognitoUserSession);
            NewDeviceMetadataType newDeviceMetadata = challenge.getAuthenticationResult().getNewDeviceMetadata();
            if (newDeviceMetadata == null) {
                return cognitoUserSession;
            }
        } else if (CognitoServiceConstants.CHLG_TYPE_USER_PASSWORD_VERIFIER.equals(challengeName)) {
            return null;
        } else if (CognitoServiceConstants.CHLG_TYPE_SMS_MFA.equals(challengeName)) {
            throw new CognitoMFARequiredException("MFA required");
        } else if (CognitoServiceConstants.CHLG_TYPE_NEW_PASSWORD_REQUIRED.equals(challengeName)) {
            throw new CognitoNewPasswordRequiredException("New Pass required");
        } else {
            throw new CognitoIdentityProviderException("Generic challenge " + challengeName);
        }
        return null;
    }

    /**
     * Determines the next step from the challenge.
     * This takes an object of type {@link InitiateAuthResult} as parameter and creates an object of type
     * {@link RespondToAuthChallengeResult} and calls {@code handleChallenge(RespondToAuthChallengeResult challenge, final AuthenticationHandler callback)} method.
     *
     * @param authResult REQUIRED: Result from the {@code initiateAuth(...)} method.
     * @return {@link Runnable} for the next step in user authentication.
     */
    private CognitoUserSession handleChallenge(final InitiateAuthResult authResult) {
        try {
            RespondToAuthChallengeResult challenge = new RespondToAuthChallengeResult();
            challenge.setChallengeName(authResult.getChallengeName());
            challenge.setSession(authResult.getSession());
            challenge.setAuthenticationResult(authResult.getAuthenticationResult());
            challenge.setChallengeParameters(authResult.getChallengeParameters());
            return handleChallenge(challenge);
        } catch (final Exception e) {
            throw new CognitoIdentityProviderException("Handlechallenge intial request failed", e);
        }
    }


    /**
     * Creates a authentication request to start authentication with user SRP verification.
     *
     * @param authenticationDetails REQUIRED: {@link AuthenticationDetails}, contains details for
     *                              user SRP authentication.
     * @param authenticationHelper  REQUIRED: Internal helper class for SRP calculations.
     * @return {@link InitiateAuthRequest}, request to start with the user SRP authentication.
     */
    private InitiateAuthRequest initiateUserSrpAuthRequest(AuthenticationDetails authenticationDetails, AuthenticationHelper authenticationHelper) {
        userId = authenticationDetails.getUserId();
        InitiateAuthRequest initiateAuthRequest = new InitiateAuthRequest();
        initiateAuthRequest.setAuthFlow(CognitoServiceConstants.AUTH_TYPE_INIT_USER_SRP);
        initiateAuthRequest.setClientId(clientId);
        initiateAuthRequest.addAuthParametersEntry(CognitoServiceConstants.AUTH_PARAM_SECRET_HASH, CognitoSecretHash.getSecretHash(userId, clientId, clientSecret));
        initiateAuthRequest.addAuthParametersEntry(CognitoServiceConstants.AUTH_PARAM_USERNAME, authenticationDetails.getUserId());
        initiateAuthRequest.addAuthParametersEntry(CognitoServiceConstants.AUTH_PARAM_SRP_A, authenticationHelper.getA().toString(16));
//        if (deviceKey == null) {
//            initiateAuthRequest.addAuthParametersEntry(CognitoServiceConstants.AUTH_PARAM_DEVICE_KEY, CognitoDeviceHelper.getDeviceKey(authenticationDetails.getUserId(), pool.getUserPoolId(), context));
//        } else {
//            initiateAuthRequest.addAuthParametersEntry(CognitoServiceConstants.AUTH_PARAM_DEVICE_KEY, deviceKey);
//        }
        if (authenticationDetails.getValidationData() != null && authenticationDetails.getValidationData().size() > 0) {
            Map<String, String> userValidationData = new HashMap<String, String>();
            for (AttributeType attribute : authenticationDetails.getValidationData()) {
                userValidationData.put(attribute.getName(), attribute.getValue());
            }
            initiateAuthRequest.setClientMetadata(userValidationData);
        }
        return initiateAuthRequest;
    }

    /**
     * Creates a authentication request to start authentication with custom authentication.
     *
     * @param authenticationDetails REQUIRED: {@link AuthenticationDetails}, contains details
     *                              required to start a custom authentication flow.
     * @return {@link InitiateAuthRequest}, request to start with the user SRP authentication.
     */
    private InitiateAuthRequest initiateCustomAuthRequest(AuthenticationDetails authenticationDetails) {
        InitiateAuthRequest authRequest = new InitiateAuthRequest();
        authRequest.setAuthFlow(CognitoServiceConstants.AUTH_TYPE_INIT_CUSTOM_AUTH);
        authRequest.setClientId(clientId);
        authRequest.setAuthParameters(authenticationDetails.getAuthenticationParameters());
        if (authenticationDetails.getValidationData() != null && authenticationDetails.getValidationData().size() > 0) {
            Map<String, String> userValidationData = new HashMap<String, String>();
            for (AttributeType attribute : authenticationDetails.getValidationData()) {
                userValidationData.put(attribute.getName(), attribute.getValue());
            }
            authRequest.setClientMetadata(userValidationData);
        }
        return authRequest;
    }

    /**
     * Creates a request to initiate device authentication.
     *
     * @param authenticationHelper REQUIRED: {@link AuthenticationDetails}, contains details
     *                             required to start a custom authentication flow.
     * @return {@link RespondToAuthChallengeRequest}, request to start device authentication.
     */
    private RespondToAuthChallengeRequest initiateDevicesAuthRequest(AuthenticationHelper authenticationHelper) {
        RespondToAuthChallengeRequest initiateDevicesAuthRequest = new RespondToAuthChallengeRequest();
        initiateDevicesAuthRequest.setClientId(clientId);
        initiateDevicesAuthRequest.setChallengeName(CognitoServiceConstants.CHLG_TYPE_DEVICE_SRP_AUTH);
        initiateDevicesAuthRequest.addChallengeResponsesEntry(CognitoServiceConstants.CHLG_RESP_USERNAME, usernameInternal);
        initiateDevicesAuthRequest.addChallengeResponsesEntry(CognitoServiceConstants.CHLG_RESP_SRP_A, authenticationHelper.getA().toString(16));
        initiateDevicesAuthRequest.addChallengeResponsesEntry(CognitoServiceConstants.CHLG_RESP_DEVICE_KEY, deviceKey);
        initiateDevicesAuthRequest.addChallengeResponsesEntry(CognitoServiceConstants.CHLG_RESP_SECRET_HASH, secretHash);

        return initiateDevicesAuthRequest;
    }

    /**
     * Creates a request to refresh tokens.
     *
     * @param currSession REQUIRED: Refresh token.
     * @return {@link InitiateAuthRequest}, request to refresh tokens.
     */
    private InitiateAuthRequest initiateRefreshTokenAuthRequest(CognitoUserSession currSession) {
        InitiateAuthRequest initiateAuthRequest = new InitiateAuthRequest();
        initiateAuthRequest.addAuthParametersEntry(CognitoServiceConstants.AUTH_PARAM_REFRESH_TOKEN, currSession.getRefreshToken().getToken());
//        if (deviceKey == null) {
//            if (usernameInternal != null) {
//                deviceKey = CognitoDeviceHelper.getDeviceKey(usernameInternal, pool.getUserPoolId(), context);
//            } else {
//                deviceKey = CognitoDeviceHelper.getDeviceKey(userId, pool.getUserPoolId(), context);
//            }
//        }
        initiateAuthRequest.addAuthParametersEntry(CognitoServiceConstants.AUTH_PARAM_DEVICE_KEY, deviceKey);
        initiateAuthRequest.addAuthParametersEntry(CognitoServiceConstants.AUTH_PARAM_SECRET_HASH, clientSecret);
        initiateAuthRequest.setClientId(clientId);
        initiateAuthRequest.setAuthFlow(CognitoServiceConstants.AUTH_TYPE_REFRESH_TOKEN);
        return initiateAuthRequest;
    }

    /**
     * Creates response for the second step of the SRP authentication.
     *
     * @param challenge             REQUIRED: {@link InitiateAuthResult} contains next challenge.
     * @param authenticationDetails REQUIRED: {@link AuthenticationDetails} user authentication details.
     * @param authenticationHelper  REQUIRED: Internal helper class for SRP calculations.
     * @return {@link RespondToAuthChallengeRequest}.
     */
    private RespondToAuthChallengeRequest userSrpAuthRequest(InitiateAuthResult challenge,
                                                             AuthenticationDetails authenticationDetails,
                                                             AuthenticationHelper authenticationHelper) {
        String userIdForSRP = challenge.getChallengeParameters().get(CognitoServiceConstants.CHLG_PARAM_USER_ID_FOR_SRP);
        this.usernameInternal = challenge.getChallengeParameters().get(CognitoServiceConstants.CHLG_PARAM_USERNAME);
        //this.deviceKey = CognitoDeviceHelper.getDeviceKey(usernameInternal, pool.getUserPoolId(), context);
        secretHash = CognitoSecretHash.getSecretHash(usernameInternal, clientId, clientSecret);

        BigInteger B = new BigInteger(challenge.getChallengeParameters().get("SRP_B"), 16);
        if (B.mod(AuthenticationHelper.N).equals(BigInteger.ZERO)) {
            throw new CognitoInternalErrorException("SRP error, B cannot be zero");
        }

        BigInteger salt = new BigInteger(challenge.getChallengeParameters().get("SALT"), 16);
        byte[] key = authenticationHelper.getPasswordAuthenticationKey(userIdForSRP, authenticationDetails.getPassword(), B, salt);

        Date timestamp = new Date();
        byte[] hmac;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            mac.init(keySpec);
            mac.update(pool.getUserPoolId().split("_", 2)[1].getBytes(StringUtils.UTF8));
            mac.update(userIdForSRP.getBytes(StringUtils.UTF8));
            byte[] secretBlock = Base64.getDecoder().decode(challenge.getChallengeParameters().get("SECRET_BLOCK"));
            mac.update(secretBlock);
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
            simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
            String dateString = simpleDateFormat.format(timestamp);
            byte[] dateBytes = dateString.getBytes(StringUtils.UTF8);
            hmac = mac.doFinal(dateBytes);
        } catch (Exception e) {
            throw new CognitoInternalErrorException("SRP error", e);
        }

        SimpleDateFormat formatTimestamp = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
        formatTimestamp.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));

        Map<String, String> srpAuthResponses = new HashMap<String, String>();
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_PASSWORD_CLAIM_SECRET_BLOCK, challenge.getChallengeParameters().get(CognitoServiceConstants.CHLG_PARAM_SECRET_BLOCK));
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_PASSWORD_CLAIM_SIGNATURE, new String(Base64.getEncoder().encode(hmac), StringUtils.UTF8));
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_TIMESTAMP, formatTimestamp.format(timestamp));
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_USERNAME, usernameInternal);
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_DEVICE_KEY, deviceKey);
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_SECRET_HASH, secretHash);

        RespondToAuthChallengeRequest authChallengeRequest = new RespondToAuthChallengeRequest();
        authChallengeRequest.setChallengeName(challenge.getChallengeName());
        authChallengeRequest.setClientId(clientId);
        authChallengeRequest.setSession(challenge.getSession());
        authChallengeRequest.setChallengeResponses(srpAuthResponses);

        return authChallengeRequest;
    }

    /**
     * Creates request for device SRP verification.
     *
     * @param challenge            REQUIRED: {@link RespondToAuthChallengeResult} contains next challenge.
     * @param deviceSecret         REQUIRED: Device secret verifier.
     * @param authenticationHelper REQUIRED: Internal helper class for SRP calculations.
     * @return {@link RespondToAuthChallengeRequest}.
     */
    public RespondToAuthChallengeRequest deviceSrpAuthRequest(RespondToAuthChallengeResult challenge,
                                                              String deviceSecret,
                                                              String deviceGroupKey,
                                                              AuthenticationHelper authenticationHelper) {
        this.usernameInternal = challenge.getChallengeParameters().get(CognitoServiceConstants.CHLG_PARAM_USERNAME);

        BigInteger B = new BigInteger(challenge.getChallengeParameters().get("SRP_B"), 16);
        if (B.mod(AuthenticationHelper.N).equals(BigInteger.ZERO)) {
            throw new CognitoInternalErrorException("SRP error, B cannot be zero");
        }

        BigInteger salt = new BigInteger(challenge.getChallengeParameters().get("SALT"), 16);
        byte[] key = authenticationHelper.getPasswordAuthenticationKey(deviceKey, deviceSecret, B, salt);

        Date timestamp = new Date();
        byte[] hmac;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            mac.init(keySpec);
            mac.update(deviceGroupKey.getBytes(StringUtils.UTF8));
            mac.update(deviceKey.getBytes(StringUtils.UTF8));
            byte[] secretBlock = Base64.getDecoder().decode(challenge.getChallengeParameters().get(CognitoServiceConstants.CHLG_PARAM_SECRET_BLOCK));
            mac.update(secretBlock);
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
            simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
            String dateString = simpleDateFormat.format(timestamp);
            byte[] dateBytes = dateString.getBytes(StringUtils.UTF8);
            hmac = mac.doFinal(dateBytes);
        } catch (Exception e) {
            throw new CognitoInternalErrorException("SRP error", e);
        }

        SimpleDateFormat formatTimestamp = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US);
        formatTimestamp.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));

        secretHash = CognitoSecretHash.getSecretHash(usernameInternal, clientId, clientSecret);

        Map<String, String> srpAuthResponses = new HashMap<String, String>();
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_PASSWORD_CLAIM_SECRET_BLOCK, challenge.getChallengeParameters().get(CognitoServiceConstants.CHLG_PARAM_SECRET_BLOCK));
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_PASSWORD_CLAIM_SIGNATURE, new String(Base64.getEncoder().encode(hmac), StringUtils.UTF8));
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_TIMESTAMP, formatTimestamp.format(timestamp));
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_USERNAME, usernameInternal);
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_DEVICE_KEY, deviceKey);
        srpAuthResponses.put(CognitoServiceConstants.CHLG_RESP_SECRET_HASH, secretHash);

        RespondToAuthChallengeRequest authChallengeRequest = new RespondToAuthChallengeRequest();
        authChallengeRequest.setChallengeName(challenge.getChallengeName());
        authChallengeRequest.setClientId(clientId);
        authChallengeRequest.setSession(challenge.getSession());
        authChallengeRequest.setChallengeResponses(srpAuthResponses);

        return authChallengeRequest;
    }


    /**
     * Returns the current device, if users in this pool can remember devices.
     *
     * @return {@link CognitoDevice} if the device is available, null otherwise.
     */
    public CognitoDevice thisDevice() {
//        if (deviceKey == null) {
//            if (usernameInternal != null) {
//                deviceKey = CognitoDeviceHelper.getDeviceKey(usernameInternal, pool.getUserPoolId(), context);
//            } else if (userId != null) {
//                deviceKey = CognitoDeviceHelper.getDeviceKey(userId, pool.getUserPoolId(), context);
//            }
//        }
//        if (deviceKey != null) {
//            return new CognitoDevice(deviceKey, null, null, null, null, this, context);
//        } else {
//            return  null;
//        }

        return null;
    }


    /**
     * Internal method to confirm a device.
     *
     * @param session          REQUIRED: A valid {@link CognitoUserSession}.
     * @param deviceKey        REQUIRED: This is the device-key assigned the new device.
     * @param passwordVerifier REQUIRED: Random string generated by the SDK.
     * @param salt             REQUIRED: Generated by the SDK to set the device verifier.
     * @param deviceName       REQUIRED: A user identifiable string assigned to the device.
     * @return {@link ConfirmDeviceResult}, service response.
     */
    private ConfirmDeviceResult confirmDeviceInternal(CognitoUserSession session, String deviceKey, String passwordVerifier, String salt, String deviceName) {
        if (session != null && session.isValid()) {
            if (deviceKey != null && deviceName != null) {
                DeviceSecretVerifierConfigType deviceConfig = new DeviceSecretVerifierConfigType();
                deviceConfig.setPasswordVerifier(passwordVerifier);
                deviceConfig.setSalt(salt);
                ConfirmDeviceRequest confirmDeviceRequest = new ConfirmDeviceRequest();
                confirmDeviceRequest.setAccessToken(session.getAccessToken().getJWTToken());
                confirmDeviceRequest.setDeviceKey(deviceKey);
                confirmDeviceRequest.setDeviceName(deviceName);
                confirmDeviceRequest.setDeviceSecretVerifierConfig(deviceConfig);
                return cognitoIdentityProviderClient.confirmDevice(confirmDeviceRequest);
            } else {
                if (deviceKey == null) {
                    throw new CognitoParameterInvalidException("Device key is null");
                } else {
                    throw new CognitoParameterInvalidException("Device name is null");
                }
            }
        } else {
            throw new CognitoNotAuthorizedException("User is not authorized");
        }
    }

    /**
     * Updates user's internal Username and device key from challenge parameters.
     *
     * @param challengeParameters REQUIRED: Challenge parameters.
     */
    private void updateInternalUsername(Map<String, String> challengeParameters) {
        if (usernameInternal == null) {
            if (challengeParameters != null && challengeParameters.containsKey(CognitoServiceConstants.CHLG_PARAM_USERNAME)) {
                usernameInternal = challengeParameters.get(CognitoServiceConstants.CHLG_PARAM_USERNAME);
                // deviceKey = CognitoDeviceHelper.getDeviceKey(usernameInternal, pool.getUserPoolId(), context);
                if (secretHash == null) {
                    secretHash = CognitoSecretHash.getSecretHash(usernameInternal, clientId, clientSecret);
                }
            }
        }
    }

    /**
     * Private class for SRP client side math.
     */
    private static class AuthenticationHelper {
        private BigInteger a;
        private BigInteger A;
        private String poolName;

        public AuthenticationHelper(String userPoolName) {
            do {
                a = new BigInteger(EPHEMERAL_KEY_LENGTH, SECURE_RANDOM).mod(N);
                A = g.modPow(a, N);
            } while (A.mod(N).equals(BigInteger.ZERO));

            if (userPoolName.contains("_")) {
                poolName = userPoolName.split("_", 2)[1];
            } else {
                poolName = userPoolName;
            }
        }

        public BigInteger geta() {
            return a;
        }

        public BigInteger getA() {
            return A;
        }

        private static final String HEX_N =
                "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                        + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                        + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                        + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                        + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                        + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                        + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                        + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                        + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                        + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                        + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
                        + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
                        + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
                        + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
                        + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
                        + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
        private static final BigInteger N = new BigInteger(HEX_N, 16);
        private static final BigInteger g = BigInteger.valueOf(2);
        private static final BigInteger k;

        private static final int EPHEMERAL_KEY_LENGTH = 1024;
        private static final int DERIVED_KEY_SIZE = 16;
        private static final String DERIVED_KEY_INFO = "Caldera Derived Key";

        private static final ThreadLocal<MessageDigest> THREAD_MESSAGE_DIGEST =
                new ThreadLocal<MessageDigest>() {
                    @Override
                    protected MessageDigest initialValue() {
                        try {
                            return MessageDigest.getInstance("SHA-256");
                        } catch (NoSuchAlgorithmException e) {
                            throw new CognitoInternalErrorException("Exception in authentication", e);
                        }
                    }
                };

        private static final SecureRandom SECURE_RANDOM;

        static {
            try {
                SECURE_RANDOM = SecureRandom.getInstance("SHA1PRNG");

                MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
                messageDigest.reset();
                messageDigest.update(N.toByteArray());
                byte[] digest = messageDigest.digest(g.toByteArray());
                k = new BigInteger(1, digest);
            } catch (NoSuchAlgorithmException e) {
                throw new CognitoInternalErrorException(e.getMessage(), e);
            }
        }

        public byte[] getPasswordAuthenticationKey(String userId,
                                                   String userPassword,
                                                   BigInteger B,
                                                   BigInteger salt) {
            // Authenticate the password
            // u = H(A, B)
            MessageDigest messageDigest = THREAD_MESSAGE_DIGEST.get();
            messageDigest.reset();
            messageDigest.update(A.toByteArray());
            BigInteger u = new BigInteger(1, messageDigest.digest(B.toByteArray()));
            if (u.equals(BigInteger.ZERO)) {
                throw new CognitoInternalErrorException("Hash of A and B cannot be zero");
            }

            // x = H(salt | H(poolName | userId | ":" | password))
            messageDigest.reset();
            messageDigest.update(poolName.getBytes(StringUtils.UTF8));
            messageDigest.update(userId.getBytes(StringUtils.UTF8));
            messageDigest.update(":".getBytes(StringUtils.UTF8));
            byte[] userIdHash = messageDigest.digest(userPassword.getBytes(StringUtils.UTF8));

            messageDigest.reset();
            messageDigest.update(salt.toByteArray());
            BigInteger x = new BigInteger(1, messageDigest.digest(userIdHash));
            BigInteger S = (B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N)).mod(N);

            Hkdf hkdf = null;
            try {
                hkdf = Hkdf.getInstance("HmacSHA256");
            } catch (NoSuchAlgorithmException e) {
                throw new CognitoInternalErrorException(e.getMessage(), e);
            }
            hkdf.init(S.toByteArray(), u.toByteArray());
            byte[] key = hkdf.deriveKey(DERIVED_KEY_INFO, DERIVED_KEY_SIZE);
            return key;
        }
    }
}
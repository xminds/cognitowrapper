package com.xminds.aws.cognito;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.SignUpRequest;
import com.amazonaws.services.cognitoidp.model.SignUpResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This represents a user-pool in a Cognito identity provider account. The user-pools are called as
 * <b>Cognito User Identity Pool</b> or <b>User Identity Pool</b> or <b>User Pool</b>. All of these
 * terms represent the same entity, which is a pool of users in your account.
 * <p>
 * A user-pool can have these:
 * <p>
 * 1) User pool ID, {@code userPoolId}. This is an unique identifier for your user pool. This is
 * a required parameter to use the SDK.
 * <p>
 * 2) Client identifier, {@code clientId}. This is generated for a user pool and each user pool
 * can have several of these. A client identifier will associated with one, and only one, user
 * pool. This is required to use the SDK. A client identifier can have one or no client secrets.
 * <p>
 * 3) Client secret, {@code clientSecret}. This is generated for a Client identified. A client
 * identifier may have a client secret, it is not necessary to generate a client secret for all
 * client identifiers. However if a client identifier has a client secret then this client secret
 * has to be used, along with the client identifier, in the SDK.
 * </p>
 * <p>
 * On a user-pool new user's can sign-up and create new {@link CognitoUser}.
 */
public class CognitoUserPool {
    /**
     * Cognito Your Identity Pool ID
     */
    private final String userPoolId;

    /**
     * Client ID created for your pool {@code userPoolId}.
     */
    private final String clientId;

    /**
     * Client secret generated for this {@code clientId}, this may be {@code null} if a secret is not
     * generated for the {@code clientId}.
     */
    private String clientSecret;


    /**
     * CIP low-level client.
     */
    private final AWSCognitoIdentityProvider client;

    /**
     * Calculated with {@code userId}, {@code clientId} and {@code clientSecret}
     */
    private String secretHash;


    /**
     * Constructs a user-pool with default {@link ClientConfiguration}.
     *
     * @param userPoolId   REQUIRED: User-pool-Id of the user-pool.
     * @param clientId     REQUIRED: Client-Id generated for this app and user-pool at the
     *                     Cognito Identity Provider developer console.
     * @param clientSecret REQUIRED: Client Secret generated for this app and user-pool at
     *                     the Cognito Identity Provider developer console.
     * @param client       REQUIRED: AWS low-level Cognito Identity Provider Client.
     */
    public CognitoUserPool(String userPoolId, String clientId, String clientSecret, AWSCognitoIdentityProvider client) {
        this.userPoolId = userPoolId;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.client = client;
    }

    /**
     * Returns Client ID set for this pool.
     *
     * @return Client ID.
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Returns Pool ID of this pool.
     *
     * @return Your User Pool ID.
     */
    public String getUserPoolId() {
        return userPoolId;
    }


    /**
     * Runs user registration in current thread.
     * <p>
     * <b>Note:</b> This method will perform network operations. Calling this method in
     * applications' main thread will cause Android to throw NetworkOnMainThreadException.
     * </p>
     *
     * @param userId         REQUIRED: userId for this user
     * @param password       REQUIRED: Password for this user
     * @param userAttributes REQUIRED: Contains all attributes for this user
     * @param validationData REQUIRED: Parameters for lambda function for user registration
     */
    public CognitoSignup signUp(final String userId, final String password,
                                final CognitoUserAttributes userAttributes,
                                final Map<String, String> validationData) {
        try {
            SignUpResult signUpResult =
                    signUpInternal(userId, password, userAttributes, validationData);
            CognitoUser user = getUser(userId);
            return new CognitoSignup(user, signUpResult.getUserConfirmed(),
                    new CognitoUserCodeDeliveryDetails(signUpResult.getCodeDeliveryDetails()));
        } catch (final Exception e) {
            throw new CognitoIdentityProviderException("Signup exception", e);
        }
    }

    /**
     * Internal method to sign-up a new user in Cognito Identity Provider user pool.
     *
     * @param userId         REQUIRED: The new user userId.
     * @param password       REQUIRED: Password you want to associate to this use.
     * @param userAttributes REQUIRED: User attributes.
     * @param validationData REQUIRED: Validation key value pairs, these will be passed to pre
     *                       and post registration lambda functions.
     * @return CognitoUser
     */
    private SignUpResult signUpInternal(String userId, String password,
                                        CognitoUserAttributes userAttributes,
                                        Map<String, String> validationData) {

        // Create a list of {@link AttributeType} from {@code userAttributes}
        List<AttributeType> validationDataList = null;
        if (validationData != null) {
            validationDataList = new ArrayList<>();
            for (Map.Entry<String, String> data : validationData.entrySet()) {
                AttributeType validation = new AttributeType();
                validation.setName(data.getKey());
                validation.setValue(data.getValue());
                validationDataList.add(validation);
            }
        }

        // Generate Client secret hash
        secretHash = CognitoSecretHash.getSecretHash(userId, clientId, clientSecret);

        // Create User registration request
        SignUpRequest signUpUserRequest = new SignUpRequest();
        signUpUserRequest.setUsername(userId);
        signUpUserRequest.setPassword(password);
        signUpUserRequest.setClientId(clientId);
        signUpUserRequest.setSecretHash(secretHash);
        signUpUserRequest.setUserAttributes(userAttributes.getAttributesList());
        signUpUserRequest.setValidationData(validationDataList);

        return client.signUp(signUpUserRequest);
    }

    /**
     * Returns last authenticated user on this device in this user pool.
     *
     * @return An instance of the {@link CognitoUser} for last authenticated, cached on this device
     */
    public CognitoUser getCurrentUser() {
//        SharedPreferences csiCachedTokens = context.getSharedPreferences("CognitoIdentityProviderCache", 0);
//
//        String csiLastUserKey = "CognitoIdentityProvider." + clientId + ".LastAuthUser";
//
//        if(csiCachedTokens.contains(csiLastUserKey)){
//            return getUser(csiCachedTokens.getString(csiLastUserKey, null));
//        }
//        else {
//            return getUser();
//        }

        return getUser();
    }

    /**
     * Returns a {@link CognitoUser} with no username set.
     *
     * @return {@link CognitoUser}.
     */
    public CognitoUser getUser() {
        return new CognitoUser(this, null, clientId, clientSecret, null, client);
    }

    /**
     * Returns a CognitoUser with userId {@code userId}
     * <p>
     * This CognitoUser is not authenticated. Call {@link CognitoUser#getSession()}
     * to get valid tokens {@link CognitoUserSession}
     * </p>
     *
     * @param userId Can be null
     * @return a new CognitoUser instance with userId {@code userId}
     */
    public CognitoUser getUser(String userId) {

        if (userId == null) {
            return getUser();
        }

        if (userId.isEmpty()) {
            return getUser();
        }

        return new CognitoUser(this, userId, clientId, clientSecret,
                CognitoSecretHash.getSecretHash(userId, clientId, clientSecret),
                client);
    }
}
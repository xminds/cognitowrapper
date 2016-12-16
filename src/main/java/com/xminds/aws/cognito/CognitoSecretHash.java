package com.xminds.aws.cognito;

import com.amazonaws.util.Base64;
import com.amazonaws.util.StringUtils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Utility class for all operations involving secret hash.
 */
public final class CognitoSecretHash {
    private final static String HMAC_SHA_256 = "HmacSHA256";

    /**
     * Generates secret hash. Uses HMAC SHA256.
     *
     * @param userId       REQUIRED: User ID
     * @param clientId     REQUIRED: Client ID
     * @param clientSecret REQUIRED: Client secret
     * @return secret hash as a {@code String}, {@code null } if {@code clinetSecret if null}
     */
    public static String getSecretHash(String userId, String clientId, String clientSecret) {
        // Arguments userId and clientId have to be not-null.
        if (userId == null) {
            throw new CognitoParameterInvalidException("user ID cannot be null");
        }

        if (clientId == null) {
            throw new CognitoParameterInvalidException("client ID cannot be null");
        }

        // Return null as secret hash if clientSecret is null.
        if (clientSecret == null) {
            return null;
        }

        SecretKeySpec signingKey = new SecretKeySpec(clientSecret.getBytes(StringUtils.UTF8),
                HMAC_SHA_256);

        try {
            Mac mac = Mac.getInstance(HMAC_SHA_256);
            mac.init(signingKey);
            mac.update(userId.getBytes(StringUtils.UTF8));
            byte[] rawHmac = mac.doFinal(clientId.getBytes(StringUtils.UTF8));
            return new String(Base64.encode(rawHmac));
        } catch (Exception e) {
            throw new CognitoInternalErrorException("errors in HMAC calculation");
        }
    }
}
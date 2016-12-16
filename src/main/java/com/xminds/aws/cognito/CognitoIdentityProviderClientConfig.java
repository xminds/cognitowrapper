package com.xminds.aws.cognito;

/**
 * Maintains SDK configuration.
 */
public final class CognitoIdentityProviderClientConfig {
    /**
     * Maximum threshold for refresh tokens, in milli seconds.
     */
    private static long REFRESH_THRESHOLD_MAX = 1800 * 1000;

    /**
     * Minimum threshold for refresh tokens, in milli seconds.
     */
    private static long REFRESH_THRESHOLD_MIN = 0;

    /**
     * Threshold for refresh tokens, in milli seconds.
     * Tokens are refreshed if the session is valid for less than this value.
     */
    private static long refreshThreshold = 300 * 1000;

    /**
     * Set the threshold for token refresh.
     *
     * @param threshold REQUIRED: Threshold for token refresh in milli seconds.
     * @throws CognitoParameterInvalidException
     */
    public static void setRefreshThreshold(long threshold) throws CognitoParameterInvalidException {
        if (threshold > REFRESH_THRESHOLD_MAX || threshold < REFRESH_THRESHOLD_MIN) {
            throw new CognitoParameterInvalidException(String.format("The value of refreshThreshold must between %d and %d seconds",
                    REFRESH_THRESHOLD_MIN, REFRESH_THRESHOLD_MAX));
        }
        refreshThreshold = threshold;
    }

    public static long getRefreshThreshold() {
        return refreshThreshold;
    }
}

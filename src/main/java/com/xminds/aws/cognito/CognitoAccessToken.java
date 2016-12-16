package com.xminds.aws.cognito;

import java.util.Date;

/**
 * Represents a access token and provides methods to read token claims.
 */

public class CognitoAccessToken extends CognitoUserToken {

    /**
     * Create a new access token.
     *
     * @param jwtToken REQUIRED: Valid JWT as a String.
     */
    public CognitoAccessToken(String jwtToken) {
        super(jwtToken);
    }

    /**
     * Returns the access token formatted as JWT.
     *
     * @return
     */
    public String getJWTToken() {
        return super.getToken();
    }

    /**
     * Returns expiration of this access token.
     *
     * @return access token expiration in UTC as java.util.Date object.
     */
    public Date getExpiration() {
        try {
            String claim = CognitoJWTParser.getClaim(super.getToken(), "exp");
            if (claim == null) {
                return null;
            }
            long epocTimeSec = Long.parseLong(claim);
            long epocTimeMilliSec = epocTimeSec * 1000;
            return new Date(epocTimeMilliSec);
        } catch (Exception e) {
            throw new CognitoInternalErrorException(e.getMessage());
        }
    }
}
package com.xminds.aws.cognito;

import java.util.Date;

public class CognitoIdToken extends CognitoUserToken {

    /**
     * Create a new id token.
     *
     * @param jwtToken REQUIRED: Valid JWT as a String.
     */
    public CognitoIdToken(String jwtToken) {
        super(jwtToken);
    }

    /**
     * Returns the id token formatted as JWT.
     *
     * @return
     */
    public String getJWTToken() {
        return super.getToken();
    }

    /**
     * Returns expiration of this id token.
     *
     * @return id token expiration claim as {@link Date} in UTC.
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
            throw new CognitoInternalErrorException(e.getMessage(), e);
        }
    }

    /**
     * Returns "not before" claim of this id token
     *
     * @return not before claim as {@link Date} in UTC.
     */
    public Date getNotBefore() {
        try {
            String claim = CognitoJWTParser.getClaim(super.getToken(), "nbf");
            if (claim == null) {
                return null;
            }
            long epocTimeSec = Long.parseLong(claim);
            long epocTimeMilliSec = epocTimeSec * 1000;
            return new Date(epocTimeMilliSec);
        } catch (Exception e) {
            throw new CognitoInternalErrorException(e.getMessage(), e);
        }
    }

    /**
     * Returns "issued at" claim of this id token
     *
     * @return issue at claim as {@link Date} in UTC.
     */
    public Date getIssuedAt() {
        try {
            String claim = CognitoJWTParser.getClaim(super.getToken(), "iat");
            if (claim == null) {
                return null;
            }
            long epocTimeSec = Long.parseLong(claim);
            long epocTimeMilliSec = epocTimeSec * 1000;
            return new Date(epocTimeMilliSec);
        } catch (Exception e) {
            throw new CognitoInternalErrorException(e.getMessage(), e);
        }
    }
}

package com.xminds.aws.cognito;

import org.apache.commons.codec.binary.Base64;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.UnsupportedEncodingException;

public class CognitoJWTParser {
    private static int HEADER = 0;
    private static int PAYLOAD = 1;
    private static int SIGNATURE = 2;

    private static Base64 urlSafeBase64;

    /**
     * Returns header for a JWT as a JSON object.
     *
     * @param JWT REQUIRED: valid JSON Web Token as String.
     * @return header as a JSONObject.
     */
    public static JSONObject getHeader(String JWT) {
        try {
            validateJWT(JWT);
            byte[] sectionDecoded = urlSafe().decode(JWT.split("\\.")[HEADER]);
            String jwtSection = new String(sectionDecoded, "UTF-8");
            return new JSONObject(jwtSection);
        } catch (UnsupportedEncodingException e) {
            throw new CognitoParameterInvalidException(e.getMessage());
        } catch (JSONException e) {
            throw new CognitoParameterInvalidException(e.getMessage());
        } catch (Exception e) {
            throw new CognitoParameterInvalidException("error in parsing JSON");
        }
    }

    /**
     * Returns payload of a JWT as a JSON object.
     *
     * @param JWT REQUIRED: valid JSON Web Token as String.
     * @return payload as a JSONObject.
     */
    public static JSONObject getPayload(String JWT) {
        try {
            validateJWT(JWT);
            String payload = JWT.split("\\.")[PAYLOAD];

            byte[] sectionDecoded = urlSafe().decode(payload);
            String jwtSection = new String(sectionDecoded, "UTF-8");
            return new JSONObject(jwtSection);
        } catch (UnsupportedEncodingException e) {
            throw new CognitoParameterInvalidException(e.getMessage());
        } catch (JSONException e) {
            throw new CognitoParameterInvalidException(e.getMessage());
        } catch (Exception e) {
            throw new CognitoParameterInvalidException("error in parsing JSON");
        }
    }

    /**
     * Returns signature of a JWT as a String.
     *
     * @param JWT REQUIRED: valid JSON Web Token as String.
     * @return signature as a String.
     */
    public static String getSignature(String JWT) {
        try {
            validateJWT(JWT);
            byte[] sectionDecoded = urlSafe().decode(JWT.split("\\.")[SIGNATURE]);
            return new String(sectionDecoded, "UTF-8");
        } catch (Exception e) {
            throw new CognitoParameterInvalidException("error in parsing JSON");
        }
    }

    /**
     * Returns a claim, from the {@code JWT}s' payload, as a String.
     *
     * @param JWT   REQUIRED: valid JSON Web Token as String.
     * @param claim REQUIRED: claim name as String.
     * @return claim from the JWT as a String.
     */
    public static String getClaim(String JWT, String claim) {
        try {
            JSONObject payload = getPayload(JWT);
            Object claimValue = payload.get(claim);

            if (claimValue != null) {
                return claimValue.toString();
            }

        } catch (Exception e) {
            throw new CognitoParameterInvalidException("invalid token");
        }
        return null;
    }


    /**
     * Checks if {@code JWT} is a valid JSON Web Token.
     *
     * @param JWT
     */
    public static void validateJWT(String JWT) {
        // Check if the the JWT has the three parts
        String[] jwtParts = JWT.split("\\.");
        if (jwtParts.length != 3) {
            throw new CognitoParameterInvalidException("not a JSON Web Token");
        }
    }


    public static Base64 urlSafe() {
        if (urlSafeBase64 == null) {
            urlSafeBase64 = new Base64(true);
        }

        return urlSafeBase64;
    }
}

package com.xminds.aws.cognito;

import com.amazonaws.services.cognitoidp.model.AttributeType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Encapsulates all user attributes and provides methods to access them.
 */
public class CognitoUserAttributes {
    /**
     * All attributes set for a user
     */
    private Map<String, String> userAttributes;

    // Multi-factor authentication options set for a user
    private Map<String, String> mfaOptions;

    /**
     * Public constructor, creates an "empty container".
     * Use {@link CognitoUserAttributes#addAttribute(String, String)} method to add user attributes.
     */
    public CognitoUserAttributes() {
        this(null);
    }

    /**
     * Constructor for internal use.
     *
     * @param userAttributes REQUIRED: Cognito user attributes as a list.
     */
    public CognitoUserAttributes(List<AttributeType> userAttributes) {
        this.userAttributes = new HashMap<String, String>();
        if (userAttributes != null) {
            for (AttributeType attribute : userAttributes) {
                this.userAttributes.put(attribute.getName(), attribute.getValue());
            }
        }
    }

    /**
     * Adds an attribute to this object.
     * <p>
     * Will add the attribute and its value. Overrides an earlier value set for an attribute
     * which was already added to this object.
     * </p>
     *
     * @param attributeName REQUIRED: The attribute name.
     * @param value         REQUIRED: Value for the attribute.
     */
    public void addAttribute(String attributeName, String value) {
        userAttributes.put(attributeName, value);
    }

    /**
     * Returns the user attributes as a key, value pairs.
     *
     * @return User attributes as key, value pairs
     */
    public Map<String, String> getAttributes() {
        return userAttributes;
    }

    /**
     * Returns the user attributes as a {@link AttributeType} list.
     *
     * @return {@link AttributeType} Cognito user attributes as a list.
     */
    protected List<AttributeType> getAttributesList() {
        List<AttributeType> attributesList = new ArrayList<>();
        if (userAttributes != null) {
            for (Map.Entry<String, String> detail : userAttributes.entrySet()) {
                AttributeType attribute = new AttributeType();
                attribute.setName(detail.getKey());
                attribute.setValue(detail.getValue());
                attributesList.add(attribute);
            }
        }
        return attributesList;
    }
}
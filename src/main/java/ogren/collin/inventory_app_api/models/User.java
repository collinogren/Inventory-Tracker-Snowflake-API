package ogren.collin.inventory_app_api.models;

import com.fasterxml.jackson.annotation.JsonProperty;

import static ogren.collin.inventory_app_api.Constants.*;

public record User(@JsonProperty(USER_ID) Long id,
                   @JsonProperty(USERNAME) String username,
                   @JsonProperty(PASSWORD) String password) {}

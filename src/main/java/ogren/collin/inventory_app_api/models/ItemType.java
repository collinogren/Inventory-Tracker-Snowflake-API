package ogren.collin.inventory_app_api.models;

import com.fasterxml.jackson.annotation.JsonProperty;

import static ogren.collin.inventory_app_api.Constants.*;

public record ItemType(@JsonProperty(ITEM_ID) Long id,
                       @JsonProperty(ITEM_NAME) String name,
                       @JsonProperty(ITEM_QUANTITY) Long quantity,
                       @JsonProperty(USER_ID) Long userId) {
}

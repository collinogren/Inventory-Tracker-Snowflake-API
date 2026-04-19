package ogren.collin.inventory_app_api.responses;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class AResponse<T> {

    private final T result;

    public AResponse(T result) {
        this.result = result;
    }

    @JsonProperty("result")
    public T getResult() {
        return result;
    }
}

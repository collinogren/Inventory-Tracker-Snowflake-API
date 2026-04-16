package ogren.collin.inventory_app_api.responses;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class AResponse<T> {

    public final T result;
    private final long timeMilliseconds;

    public AResponse(T result, long timeMilliseconds) {
        this.result = result;
        this.timeMilliseconds = timeMilliseconds;
    }

    public T getResult() {
        return result;
    }

    @JsonProperty("time_ms")
    public long timeMilliseconds() {
        return this.timeMilliseconds;
    }
}

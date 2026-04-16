package ogren.collin.inventory_app_api.responses;

import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class AResponse<T> {

    private final T result;
    private final long timeMilliseconds;

    public AResponse(T result, long timeMilliseconds) {
        this.result = result;
        this.timeMilliseconds = timeMilliseconds;
    }

    @JsonProperty("result")
    public T getResult() {
        return result;
    }

    @JsonProperty("time_ms")
    public long getTimeMilliseconds() {
        return this.timeMilliseconds;
    }
}

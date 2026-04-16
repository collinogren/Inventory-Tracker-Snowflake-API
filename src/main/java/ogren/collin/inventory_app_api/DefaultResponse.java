package ogren.collin.inventory_app_api;

import com.fasterxml.jackson.annotation.JsonProperty;

public class DefaultResponse {

	private final String result;
	private final long timeMilliseconds;

	public DefaultResponse() {
		this.result = "Nothing to see here";
		this.timeMilliseconds = 0;
	}

	public String getResult() {
		return this.result;
	}

	@JsonProperty("time_ms")
	public long getTimeMilliseconds() {
		return this.timeMilliseconds;
	}
}

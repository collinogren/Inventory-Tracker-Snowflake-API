package ogren.collin.inventory_app_api;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import tools.jackson.databind.ObjectMapper;

public record ApiGatewayResponse(int statusCode, String body, Map<String, String> headers, boolean isBase64Encoded) {

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {

		private static final Logger LOG = LogManager.getLogger();

		private static final ObjectMapper objectMapper = new ObjectMapper();

		private int statusCode = 200;
		private Map<String, String> headers = Collections.emptyMap();
		private String rawBody;
		private Object objectBody;
		private byte[] binaryBody;
		private boolean base64Encoded;

		public Builder setStatusCode(int statusCode) {
			this.statusCode = statusCode;
			return this;
		}

		public Builder setHeaders(Map<String, String> headers) {
			this.headers = headers;
			return this;
		}

		public Builder setRawBody(String rawBody) {
			this.rawBody = rawBody;
			return this;
		}

		public Builder setObjectBody(Object objectBody) {
			this.objectBody = objectBody;
			return this;
		}

		public Builder setBinaryBody(byte[] binaryBody) {
			this.binaryBody = binaryBody;
			setBase64Encoded(true);
			return this;
		}

		public Builder setBase64Encoded(boolean base64Encoded) {
			this.base64Encoded = base64Encoded;
			return this;
		}

		public ApiGatewayResponse build() {
			String body = null;
			if (rawBody != null) {
				body = rawBody;
			} else if (objectBody != null) {
				try {
					body = objectMapper.writeValueAsString(objectBody);
				} catch (Exception e) {
					throw new RuntimeException(e);
				}
			} else if (binaryBody != null) {
				body = new String(Base64.getEncoder().encode(binaryBody), StandardCharsets.UTF_8);
			}
			return new ApiGatewayResponse(statusCode, body, headers, base64Encoded);
		}
	}
}

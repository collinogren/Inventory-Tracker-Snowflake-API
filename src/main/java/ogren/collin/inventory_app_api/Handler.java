package ogren.collin.inventory_app_api;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.*;
import java.util.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import ogren.collin.inventory_app_api.models.ItemType;
import ogren.collin.inventory_app_api.models.User;
import ogren.collin.inventory_app_api.responses.AResponse;
import ogren.collin.inventory_app_api.responses.MutationResponse;
import ogren.collin.inventory_app_api.responses.Response;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

import static ogren.collin.inventory_app_api.Constants.*;

public class Handler implements RequestHandler<Map<String, Object>, ApiGatewayResponse> {

	private static final Logger LOGGER = LogManager.getLogger(Handler.class);
	private static final Map<String, String> HEADERS = new HashMap<>();
	private static final MessageDigest messageDigest;


	static {
		HEADERS.put("Content-Type", "application/json");
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

	private static class Connector {
		private static Connection connection = null;

		private static class PrivateKeyReader {
			private static PrivateKey get(String key) throws Exception {
				if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
					Security.addProvider(new BouncyCastleProvider());
				}

				if (key == null || key.isBlank()) {
					throw new IllegalArgumentException("Private key is null or empty");
				}

				key = key.replace("\\n", "\n").trim();

				LogManager.getLogger(PrivateKeyReader.class).info(key.substring(0, Math.min(100, key.length())));

				PEMParser pemParser = new PEMParser(new StringReader(key));
				Object object = pemParser.readObject();
				pemParser.close();

				JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);

				if (object instanceof PrivateKeyInfo) {
					return converter.getPrivateKey((PrivateKeyInfo) object);
				} else if (object instanceof PEMKeyPair) {
					return converter.getKeyPair((PEMKeyPair) object).getPrivate();
				} else {
					throw new IllegalArgumentException("Unsupported key format: " + object);
				}
			}
		}

		public static Connection connect() throws Exception {
			if (connection == null || connection.isClosed() || !connection.isValid(5)) {
				Map<String, String> env = System.getenv();
				Properties props = new Properties();
				props.put("CLIENT_SESSION_KEEP_ALIVE", true);
				props.put("account", env.get("SNOWFLAKE_ACCOUNT"));
				props.put("user", env.get("SNOWFLAKE_USER"));
				props.put("privateKey", PrivateKeyReader.get(env.get("SNOWFLAKE_PRIVATE_KEY")));
				props.put("warehouse", env.get("SNOWFLAKE_WAREHOUSE"));
				props.put("db", env.get("SNOWFLAKE_DATABASE"));
				props.put("schema", env.get("SNOWFLAKE_SCHEMA"));
				props.put("JDBC_QUERY_RESULT_FORMAT", "JSON");
				String url = "jdbc:snowflake://" + env.get("SNOWFLAKE_ACCOUNT") + ".snowflakecomputing.com/";
				connection = DriverManager.getConnection(url, props);
				return connection;
			}
			return connection;
		}
	}

	private ApiGatewayResponse handleDefault() {
		return ApiGatewayResponse.builder()
				.setStatusCode(200)
				.setObjectBody(new DefaultResponse())
				.setHeaders(HEADERS)
				.build();
	}

	private ApiGatewayResponse handleBadRequest() {
		return ApiGatewayResponse.builder()
				.setStatusCode(400)
				.setObjectBody(new DefaultResponse())
				.setHeaders(HEADERS)
				.build();
	}

	private ApiGatewayResponse handleInternalServerError() {
		return ApiGatewayResponse.builder()
				.setStatusCode(500)
				.setObjectBody(new DefaultResponse())
				.setHeaders(HEADERS)
				.build();
	}

	private ApiGatewayResponse handleSuccess(Object response) {
		return ApiGatewayResponse.builder()
				.setStatusCode(200)
				.setObjectBody(response)
				.setHeaders(HEADERS).build();
	}

	private PreparedStatement userLoginPreparedStatement(
			String username,
			String passwordHash,
			Connection connection
	) throws Exception {
		String sql = """
				select *
				from INVENTORY_USERS
				where username = ?
				and password_hash = ?;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, username);
		statement.setString(2, passwordHash);

		return statement;
	}

	private PreparedStatement userRegisterPreparedStatement(
			String username,
			String passwordHash,
			Connection connection
	) throws Exception {
		String sql = """
			merge into INVENTORY_USERS as i_users
			using (select ? as username_value, ? as password_hash) as source
			on i_users.USERNAME = source.username_value
			when not matched then
			insert (USERNAME, PASSWORD_HASH) values (source.username_value, source.password_hash)
			""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, username);
		statement.setString(2, passwordHash);

		return statement;
	}

	private PreparedStatement itemCreatePreparedStatement(
			String itemName,
			int itemQuantity,
			int userID,
			Connection connection) throws Exception	{
		String sql = """
				insert into INVENTORY (ITEM_NAME, ITEM_QUANTITY, USER_ID)
				values (?, ?, ?);""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, itemName);
		statement.setInt(2, itemQuantity);
		statement.setInt(3, userID);

		return statement;
	}

	private PreparedStatement itemGetOnePreparedStatement(
			int itemID,
			int userID,
			Connection connection
	) throws Exception {

		String sql = """
			select *
			from INVENTORY
			where ID = ?
			and USER_ID = ?
			limit 1;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setInt(1, itemID);
		statement.setInt(2, userID);

		return statement;
	}

	private PreparedStatement itemGetAllPreparedStatement(
			int userID,
			Connection connection
	) throws Exception {
		String sql = """
			select *
			from INVENTORY
			where USER_ID = ?;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setInt(1, userID);

		return statement;
	}

	private PreparedStatement itemSearchPreparedStatement(
			String itemName,
			int userID,
			Connection connection
	) throws Exception {
		String sql = """
			select ID, ITEM_NAME, ITEM_QUANTITY, JAROWINKLER_SIMILARITY(ITEM_NAME, ?) as similarity_score, USER_ID
			from INVENTORY
			where USER_ID = ?
			order by similarity_score DESC;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, itemName);
		statement.setInt(2, userID);
		statement.setString(3, itemName);

		return statement;
	}

	private PreparedStatement itemEditPreparedStatement(
			String itemName,
			int itemQuantity,
			int itemID,
			int userID,
			Connection connection) throws Exception	{
		String sql = """
				update INVENTORY
				set ITEM_NAME = ?,
					ITEM_QUANTITY = ?
				where ID = ?
				and USER_ID = ?;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, itemName);
		statement.setInt(2, itemQuantity);
		statement.setInt(3, itemID);
		statement.setInt(4, userID);

		return statement;
	}

	private PreparedStatement itemDeletePreparedStatement(
			int itemID,
			int userID,
			Connection connection
	) throws Exception {
		String sql = """
			delete from INVENTORY
			where ID = ?
			and USER_ID = ?;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setInt(1, itemID);
		statement.setInt(2, userID);

		return statement;
	}

	private PreparedStatementWrapper<User> handleUserLogin(Map<String, Object> body) throws Exception {
		if (body == null) return null;

		String username = (String) body.get(USERNAME);
		String password = (String) body.get(PASSWORD);

		if (username == null || password == null) return null;

		String passwordHash = HexFormat.of().formatHex(messageDigest.digest(password.getBytes(StandardCharsets.UTF_8)));
		Connection connection = Connector.connect();
		return new PreparedStatementWrapper<>(userLoginPreparedStatement(username, passwordHash, connection), User.class);
	}

	private PreparedStatementWrapper<Integer> handleUserRegister(Map<String, Object> body) throws Exception {
		if (body == null) return null;

		String username = (String) body.get(USERNAME);
		String password = (String) body.get(PASSWORD);

		if (username == null || password == null) return null;

		String passwordHash = HexFormat.of().formatHex(messageDigest.digest(password.getBytes(StandardCharsets.UTF_8)));
		Connection connection = Connector.connect();
		return new PreparedStatementWrapper<>(userRegisterPreparedStatement(username, passwordHash, connection), Integer.class);
	}

	private PreparedStatementWrapper<Integer> handleItemCreate(Map<String, Object> body) throws Exception {
		String itemName = (String) body.get(ITEM_NAME);
		String itemQuantityString = String.valueOf(body.get(ITEM_QUANTITY));
		String userIDString = String.valueOf(body.get(USER_ID));

		int itemQuantity;
		int userID;
		try {
			itemQuantity = Integer.parseInt(itemQuantityString);
			userID = Integer.parseInt(userIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return new PreparedStatementWrapper<>(itemCreatePreparedStatement(itemName, itemQuantity, userID, connection), Integer.class);
	}

	private PreparedStatementWrapper<ItemType> handleItemGetOne(Map<String, Object> body) throws Exception {
		String itemIDString = String.valueOf(body.get(ITEM_ID));
		String userIDString = String.valueOf(body.get(USER_ID));

		if (itemIDString == null || userIDString == null) return null;

		int itemID;
		int userID;
		try {
			itemID = Integer.parseInt(itemIDString);
			userID = Integer.parseInt(userIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return new PreparedStatementWrapper<>(itemGetOnePreparedStatement(itemID, userID, connection), ItemType.class);
	}

	private PreparedStatementWrapper<ItemType> handleItemGetAll(Map<String, Object> body) throws Exception {
		String userIDString = String.valueOf(body.get(USER_ID));

		if (userIDString == null) return null;

		int userID;
		try {
			userID = Integer.parseInt(userIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return new PreparedStatementWrapper<>(itemGetAllPreparedStatement(userID, connection), ItemType.class);
	}

	private PreparedStatementWrapper<ItemType> handleItemSearch(Map<String, Object> body) throws Exception {
		String itemName = String.valueOf(body.get(ITEM_NAME));
		String userIDString = String.valueOf(body.get(USER_ID));

		if (itemName == null || userIDString == null) return null;

		int userID;
		try {
			userID = Integer.parseInt(userIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();

		if (itemName.isEmpty()) {
			return new PreparedStatementWrapper<>(itemGetAllPreparedStatement(userID, connection), ItemType.class);
		}

		return new PreparedStatementWrapper<>(itemSearchPreparedStatement(itemName, userID, connection), ItemType.class);
	}

	private PreparedStatementWrapper<Integer> handleItemEdit(Map<String, Object> body) throws Exception {
		String itemName = (String) body.get(ITEM_NAME);
		String itemQuantityString = String.valueOf(body.get(ITEM_QUANTITY));
		String itemIDString = String.valueOf(body.get(ITEM_ID));
		String userIDString = String.valueOf(body.get(USER_ID));

		int itemQuantity;
		int itemID;
		int userID;
		try {
			itemQuantity = Integer.parseInt(itemQuantityString);
			itemID = Integer.parseInt(itemIDString);
			userID = Integer.parseInt(userIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return new PreparedStatementWrapper<>(itemEditPreparedStatement(itemName, itemQuantity, itemID, userID, connection), Integer.class);
	}

	private PreparedStatementWrapper<Integer> handleItemDelete(Map<String, Object> body) throws Exception {
		String itemIDString = String.valueOf(body.get(ITEM_ID));
		String userIDString = String.valueOf(body.get(USER_ID));

		int itemID;
		int userID;
		try {
			itemID = Integer.parseInt(itemIDString);
			userID = Integer.parseInt(userIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return new PreparedStatementWrapper<>(itemDeletePreparedStatement(itemID, userID, connection), Integer.class);
	}

	private final ObjectMapper mapper = new ObjectMapper();

	@Override
	@SuppressWarnings("unchecked")
	public ApiGatewayResponse handleRequest(Map<String, Object> input, Context context) {
		String path = (String) input.get("path");
		String body = (String) input.get("body");

		try {
			Map<String, Object> bodyParameters = body != null ?
					mapper.readValue(body, new TypeReference<>() {}) :
					new HashMap<>();

			if (!HTTP_ROUTES.contains(path)) {
				return handleDefault();
			}

			AResponse<?> response = getResponse(path, bodyParameters);
			if (response == null) {
				return handleBadRequest();
			}

			return handleSuccess(response);
		} catch (Exception e) {
			LOGGER.error(e);
			return new ApiGatewayResponse(500, "{\"error\":\"" + e.getMessage() + "\"}", HEADERS, false);
		}
	}

	private AResponse<?> getResponse(String path, Map<String, Object> bodyParameters) throws Exception {
		Response readResponse = tryReadResponses(path, bodyParameters);
		MutationResponse writeResponse = tryWriteResponses(path, bodyParameters);

		if (readResponse != null) {
			return readResponse;
		} else return writeResponse;
	}

	private Response tryReadResponses(String path, Map<String, Object> bodyParameters) throws Exception {
		ResultSet resultSet;
		try (PreparedStatementWrapper<?> wrappedPreparedStatement = switch (path) {
			case USERS_LOGIN -> handleUserLogin(bodyParameters);
			case ITEMS_GET_ONE -> handleItemGetOne(bodyParameters);
			case ITEMS_GET_ALL -> handleItemGetAll(bodyParameters);
			case ITEMS_SEARCH -> handleItemSearch(bodyParameters);
			default -> null;
		}) {
			if (wrappedPreparedStatement == null) {
				return null;
			}

			PreparedStatement statement = wrappedPreparedStatement.preparedStatement();
			Class<?> expectedType = wrappedPreparedStatement.expectedType();

			resultSet = statement.executeQuery();

			ArrayList<Object> results = new ArrayList<>();

			while (resultSet.next()) {
				results.add(serializeData(resultSet, expectedType));
			}

			return new Response(results);
		}
	}

	private <T> Object serializeData(ResultSet resultSet, Class<T> expectedType) throws SQLException {
		if (expectedType == User.class) {
			return new User(
					resultSet.getLong("ID"),
					resultSet.getString("USERNAME"),
					resultSet.getString("PASSWORD_HASH"));
		} else if (expectedType == ItemType.class) {
			return new ItemType(
					resultSet.getLong("ID"),
					resultSet.getString("ITEM_NAME"),
					resultSet.getLong("ITEM_QUANTITY"),
					resultSet.getLong("USER_ID"));
		} else {
			return null;
		}
	}

	private MutationResponse tryWriteResponses(String path, Map<String, Object> bodyParameters) throws Exception {
		int rowsAffected;
		try (PreparedStatementWrapper<?> statement = switch (path) {
			case USERS_REGISTER -> handleUserRegister(bodyParameters);
			case ITEMS_CREATE -> handleItemCreate(bodyParameters);
			case ITEMS_EDIT -> handleItemEdit(bodyParameters);
			case ITEMS_DELETE -> handleItemDelete(bodyParameters);
			default -> null;
		}) {
			if (statement == null) {
				return null;
			}

			rowsAffected = statement.preparedStatement().executeUpdate();

			return new MutationResponse(rowsAffected);
		}
	}
}

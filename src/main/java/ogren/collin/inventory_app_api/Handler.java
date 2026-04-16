package ogren.collin.inventory_app_api;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.*;
import java.util.*;

import ogren.collin.inventory_app_api.responses.AResponse;
import ogren.collin.inventory_app_api.responses.MutationResponse;
import ogren.collin.inventory_app_api.responses.Response;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

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

				key = key.replace("\\n", "\n");
				PEMParser pemParser = new PEMParser(new StringReader(key));
				PrivateKeyInfo keyInfo = (PrivateKeyInfo) pemParser.readObject();
				pemParser.close();
				JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
				return converter.getPrivateKey(keyInfo);
			}
		}

		public static Connection connect() throws Exception {
			if (connection == null) {
				Map<String, String> env = System.getenv();
				Properties props = new Properties();
				props.put("CLIENT_SESSION_KEEP_ALIVE", true);
				props.put("account", env.get("SNOWFLAKE_ACCOUNT"));
				props.put("user", env.get("SNOWFLAKE_USER"));
				props.put("privateKey", PrivateKeyReader.get(env.get("SNOWFLAKE_PRIVATE_KEY")));
				props.put("warehouse", env.get("SNOWFLAKE_WAREHOUSE"));
				props.put("db", env.get("SNOWFLAKE_DATABASE"));
				props.put("schema", env.get("SNOWFLAKE_SCHEMA"));
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
				insert into INVENTORY_USERS (PASSWORD_HASH, USERNAME)
				values (?, ?);""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, passwordHash);
		statement.setString(2, username);

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
			select ID, ITEM_NAME, ITEM_QUANTITY
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
			select ID, ITEM_NAME, ITEM_QUANTITY
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
			set search_term = ?;
			
			select ID, ITEM_NAME, ITEM_QUANTITY, JAROWINKLER_SIMILARITY(ITEM_NAME, $search_term) as similarity_score
			from INVENTORY
			where USER_ID = ?
			and JAROWINKLER_SIMILARITY(ITEM_NAME, $search_term) >= 80
			order by similarity_score DESC;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, itemName);
		statement.setInt(2, userID);

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

	private PreparedStatement handleUserLogin(Map<String, Object> body) throws Exception {
		if (body == null) return null;

		String username = (String) body.get(USERNAME);
		String password = (String) body.get(PASSWORD);

		if (username == null || password == null) return null;

		String passwordHash = Arrays.toString(messageDigest.digest(password.getBytes(StandardCharsets.UTF_8)));
		Connection connection = Connector.connect();
		return userLoginPreparedStatement(username, passwordHash, connection);
	}

	private PreparedStatement handleUserRegister(Map<String, Object> body) throws Exception {
		if (body == null) return null;

		String username = (String) body.get(USERNAME);
		String password = (String) body.get(PASSWORD);

		if (username == null || password == null) return null;

		String passwordHash = Arrays.toString(messageDigest.digest(password.getBytes(StandardCharsets.UTF_8)));
		Connection connection = Connector.connect();
		return userRegisterPreparedStatement(username, passwordHash, connection);
	}

	private PreparedStatement handleItemCreate(Map<String, Object> body) throws Exception {
		String itemName = (String) body.get(ITEM_NAME);
		String itemQuantityString = (String) body.get(ITEM_QUANTITY);
		String userIDString = (String) body.get(USER_ID);

		int itemQuantity;
		int userID;
		try {
			itemQuantity = Integer.parseInt(itemQuantityString);
			userID = Integer.parseInt(userIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return itemCreatePreparedStatement(itemName, itemQuantity, userID, connection);
	}

	private PreparedStatement handleItemGetOne(Map<String, Object> body) throws Exception {
		String itemIDString = (String) body.get(ITEM_ID);
		String userIDString = (String) body.get(USER_ID);

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
		return itemGetOnePreparedStatement(itemID, userID, connection);
	}

	private PreparedStatement handleItemGetAll(Map<String, Object> body) throws Exception {
		String userIDString = (String) body.get(USER_ID);

		if (userIDString == null) return null;

		int userID;
		try {
			userID = Integer.parseInt(userIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return itemGetAllPreparedStatement(userID, connection);
	}

	private PreparedStatement handleItemSearch(Map<String, Object> body) throws Exception {
		String itemName = (String) body.get(ITEM_NAME);
		String userIDString = (String) body.get(USER_ID);

		if (itemName == null || userIDString == null) return null;

		int userID;
		try {
			userID = Integer.parseInt(userIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();

		if (itemName.isEmpty()) {
			return itemGetAllPreparedStatement(userID, connection);
		}

		return itemSearchPreparedStatement(itemName, userID, connection);
	}

	private PreparedStatement handleItemEdit(Map<String, Object> body) throws Exception {
		String itemName = (String) body.get(ITEM_NAME);
		String itemQuantityString = (String) body.get(ITEM_QUANTITY);
		String itemIDString = (String) body.get(ITEM_ID);
		String userIDString = (String) body.get(USER_ID);

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
		return itemEditPreparedStatement(itemName, itemQuantity, itemID, userID, connection);
	}

	private PreparedStatement handleItemDelete(Map<String, Object> body) throws Exception {
		String itemIDString = (String) body.get(ITEM_ID);
		String userIDString = (String) body.get(USER_ID);

		int itemID;
		int userID;
		try {
			itemID = Integer.parseInt(itemIDString);
			userID = Integer.parseInt(userIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return itemDeletePreparedStatement(itemID, userID, connection);
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
		try (PreparedStatement statement = switch (path) {
			case ITEMS_GET_ONE -> handleItemGetOne(bodyParameters);
			case ITEMS_GET_ALL -> handleItemGetAll(bodyParameters);
			case ITEMS_SEARCH -> handleItemSearch(bodyParameters);
			default -> null;
		}) {
			if (statement == null) {
				return null;
			}

			long startTime = System.nanoTime();

			resultSet = statement.executeQuery();

			long timeMilliseconds = (System.nanoTime() - startTime) / 1000000;
			ArrayList<Object[]> results = new ArrayList<>();

			while (resultSet.next()) {
				ArrayList<Object> objects = new ArrayList<>();
				for (int i = 1; i <= resultSet.getMetaData().getColumnCount(); i++) {
					objects.add(resultSet.getObject(i));
				}

				results.add(objects.toArray());
			}

			return new Response(results, timeMilliseconds);
		}
	}

	private MutationResponse tryWriteResponses(String path, Map<String, Object> bodyParameters) throws Exception {
		int rowsAffected;
		try (PreparedStatement statement = switch (path) {
			case USERS_LOGIN -> handleUserLogin(bodyParameters);
			case USERS_REGISTER -> handleUserRegister(bodyParameters);
			case ITEMS_CREATE -> handleItemCreate(bodyParameters);
			case ITEMS_EDIT -> handleItemEdit(bodyParameters);
			case ITEMS_DELETE -> handleItemDelete(bodyParameters);
			default -> null;
		}) {
			if (statement == null) {
				return null;
			}

			long startTime = System.nanoTime();

			rowsAffected = statement.executeUpdate();

			long timeMilliseconds = (System.nanoTime() - startTime) / 1000000;

			return new MutationResponse(rowsAffected, timeMilliseconds);
		}
	}
}

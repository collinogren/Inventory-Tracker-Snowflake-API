package ogren.collin.inventory_app_api;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.PreparedStatement;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;

public class Handler implements RequestHandler<Map<String, Object>, ApiGatewayResponse> {

	private static final Logger LOG = LogManager.getLogger();
	private static final Map<String, String> HEADERS = new HashMap<>();
	private static final MessageDigest messageDigest;
	private static final Set<String> HTTP_ROUTES = Set.of(
		"/users/login", "/users/register", "/work_groups/create",
		"items/create", "items/get_one", "items/get_all",
		"items/search", "items/edit", "items/delete"
	);

	static {
		HEADERS.put("Content-Type", "application/json");
		Security.addProvider(new BouncyCastleProvider());
        try {
            messageDigest = MessageDigest.getInstance("SHA-256", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

	private static class Connector {
		private static Connection connection = null;

		private static class PrivateKeyReader {
			private static PrivateKey get(String key) throws Exception {
				Security.addProvider(new BouncyCastleProvider());
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
				return DriverManager.getConnection(url, props);
			}
			return connection;
		}
	}

	private ApiGatewayResponse handleDefault() {
		return ApiGatewayResponse.builder().setStatusCode(200).setObjectBody(new DefaultResponse()).setHeaders(HEADERS)
				.build();
	}

	private ApiGatewayResponse handleBadRequest() {
		return ApiGatewayResponse.builder().setStatusCode(400).setObjectBody(new DefaultResponse()).setHeaders(HEADERS)
				.build();
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
			int workGroupID,
			Connection connection
	) throws Exception {
		String sql = """
				insert into INVENTORY_USERS (PASSWORD_HASH, USERNAME, WORK_GROUP_ID)
    			values (?, ?, ?);""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, passwordHash);
		statement.setString(2, username);
		statement.setInt(3, workGroupID);

		return statement;
	}

	private PreparedStatement workGroupCreatePreparedStatement(
			String workGroupName,
			String joinPasswordHash,
			String adminPasswordHash,
			Connection connection
	) throws Exception {
		String sql = """
				insert into WORK_GROUPS (GROUP_NAME, JOIN_PASSWORD_HASH, ADMIN_PASSWORD_HASH)
				values (?, ?, ?);""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, workGroupName);
		statement.setString(2, joinPasswordHash);
		statement.setString(3, adminPasswordHash);

		return statement;
	}

	private PreparedStatement itemCreatePreparedStatement(
			String itemName,
			int itemQuantity,
			int workGroupID,
			Connection connection) throws Exception	{
		String sql = """
				insert into INVENTORY (ITEM_NAME, ITEM_QUANTITY, WORK_GROUP_ID)
				values (?, ?, ?);""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, itemName);
		statement.setInt(2, itemQuantity);
		statement.setInt(3, workGroupID);

		return statement;
	}

	private PreparedStatement itemGetOnePreparedStatement(
			int itemID,
			int workGroupID,
			Connection connection
	) throws Exception {

		String sql = """
			select ID, ITEM_NAME, ITEM_QUANTITY
			from INVENTORY
			where ID = ?
			and WORK_GROUP_ID = ?
			limit 1;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setInt(1, itemID);
		statement.setInt(2, workGroupID);

		return statement;
	}

	private PreparedStatement itemGetAllPreparedStatement(
			int workGroupID,
			Connection connection
	) throws Exception {
		String sql = """
			select ID, ITEM_NAME, ITEM_QUANTITY
			from INVENTORY
			where WORK_GROUP_ID = ?;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setInt(1, workGroupID);

		return statement;
	}

	private PreparedStatement itemSearchPreparedStatement(
			String itemName,
			int workGroupID,
			Connection connection
	) throws Exception {
		String sql = """
			set search_term = ?;
			
			select ID, ITEM_NAME, ITEM_QUANTITY, JAROWINKLER_SIMILARITY(ITEM_NAME, $search_term) as similarity_score
			from INVENTORY
			where WORK_GROUP_ID = ?
			and JAROWINKLER_SIMILARITY(ITEM_NAME, $search_term) >= 80
			order by similarity_score DESC;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, itemName);
		statement.setInt(2, workGroupID);

		return statement;
	}

	private PreparedStatement itemEditPreparedStatement(
			String itemName,
			int itemQuantity,
			int itemID,
			int workGroupID,
			Connection connection) throws Exception	{
		String sql = """
				update INVENTORY
				set ITEM_NAME = ?,
					ITEM_QUANTITY = ?
				where ID = ?
				and WORK_GROUP_ID = ?;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setString(1, itemName);
		statement.setInt(2, itemQuantity);
		statement.setInt(3, itemID);
		statement.setInt(4, workGroupID);

		return statement;
	}

	private PreparedStatement itemDeletePreparedStatement(
			int itemID,
			int workGroupID,
			Connection connection
	) throws Exception {
		String sql = """
			delete from INVENTORY
			where ID = ?
			and WORK_GROUP_ID = ?;""";

		PreparedStatement statement = connection.prepareStatement(sql);
		statement.setInt(1, itemID);
		statement.setInt(2, workGroupID);

		return statement;
	}

	private PreparedStatement handleUserLogin(Map<String, String> headers) throws Exception {
		if (headers == null) return null;

		String username = headers.get("username");
		String password = headers.get("password");

		if (username == null || password == null) return null;

		String passwordHash = Arrays.toString(messageDigest.digest(password.getBytes(StandardCharsets.UTF_8)));
		Connection connection = Connector.connect();
		return userLoginPreparedStatement(username, passwordHash, connection);
	}

	private PreparedStatement handleUserRegister(Map<String, String> headers) throws Exception {
		if (headers == null) return null;

		String username = headers.get("username");
		String password = headers.get("password");
		String workGroupIDString = headers.get("workGroupID");

		if (username == null || password == null) return null;

		int workGroupID;
		try {
			workGroupID = Integer.parseInt(workGroupIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		String passwordHash = Arrays.toString(messageDigest.digest(password.getBytes(StandardCharsets.UTF_8)));
		Connection connection = Connector.connect();
		return userRegisterPreparedStatement(username, passwordHash, workGroupID, connection);
	}

	private PreparedStatement handleWorkGroupCreate(Map<String, String> headers) throws Exception {
		if (headers == null) return null;

		String workGroupName = headers.get("workGroupName");
		String joinPassword = headers.get("joinPassword");
		String adminPassword = headers.get("adminPassword");

		if (workGroupName == null || joinPassword == null || adminPassword == null) return null;

		String joinPasswordHash = Arrays.toString(messageDigest.digest(joinPassword.getBytes(StandardCharsets.UTF_8)));
		String adminPasswordHash = Arrays.toString(messageDigest.digest(adminPassword.getBytes(StandardCharsets.UTF_8)));

		Connection connection = Connector.connect();
		return workGroupCreatePreparedStatement(workGroupName, joinPasswordHash, adminPasswordHash, connection);
	}

	private PreparedStatement handleItemCreate(Map<String, String> headers) throws Exception {
		String itemName = headers.get("itemName");
		String itemQuantityString = headers.get("itemQuantity");
		String workGroupIDString = headers.get("workGroupID");

		int itemQuantity;
		int workGroupID;
		try {
			itemQuantity = Integer.parseInt(itemQuantityString);
			workGroupID = Integer.parseInt(workGroupIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return itemCreatePreparedStatement(itemName, itemQuantity, workGroupID, connection);
	}

	private PreparedStatement handleItemGetOne(Map<String, String> headers) throws Exception {
		String itemIDString = headers.get("itemID");
		String workGroupIDString = headers.get("workGroupID");

		if (itemIDString == null || workGroupIDString == null) return null;

		int itemID;
		int workGroupID;
		try {
			itemID = Integer.parseInt(itemIDString);
			workGroupID = Integer.parseInt(workGroupIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return itemGetOnePreparedStatement(itemID, workGroupID, connection);
	}

	private PreparedStatement handleItemGetAll(Map<String, String> headers) throws Exception {
		String workGroupIDString = headers.get("workGroupID");

		if (workGroupIDString == null) return null;

		int workGroupID;
		try {
			workGroupID = Integer.parseInt(workGroupIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return itemGetAllPreparedStatement(workGroupID, connection);
	}

	private PreparedStatement handleItemSearch(Map<String, String> headers) throws Exception {
		String itemName = headers.get("itemName");
		String workGroupIDString = headers.get("workGroupID");

		if (itemName == null || workGroupIDString == null) return null;

		int workGroupID;
		try {
			workGroupID = Integer.parseInt(workGroupIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();

		if (itemName.isEmpty()) {
			return itemGetAllPreparedStatement(workGroupID, connection);
		}

		return itemSearchPreparedStatement(itemName, workGroupID, connection);
	}

	private PreparedStatement handleItemEdit(Map<String, String> headers) throws Exception {
		String itemName = headers.get("itemName");
		String itemQuantityString = headers.get("itemQuantity");
		String itemIDString = headers.get("itemID");
		String workGroupIDString = headers.get("workGroupID");

		int itemQuantity;
		int itemID;
		int workGroupID;
		try {
			itemQuantity = Integer.parseInt(itemQuantityString);
			itemID = Integer.parseInt(itemIDString);
			workGroupID = Integer.parseInt(workGroupIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return itemEditPreparedStatement(itemName, itemQuantity, itemID, workGroupID, connection);
	}

	private PreparedStatement handleItemDelete(Map<String, String> headers) throws Exception {
		String itemIDString = headers.get("itemID");
		String workGroupIDString = headers.get("workGroupID");

		int itemID;
		int workGroupID;
		try {
			itemID = Integer.parseInt(itemIDString);
			workGroupID = Integer.parseInt(workGroupIDString);
		} catch (NumberFormatException _) {
			return null;
		}

		Connection connection = Connector.connect();
		return itemDeletePreparedStatement(itemID, workGroupID, connection);
	}

	@Override
	@SuppressWarnings("unchecked")
	public ApiGatewayResponse handleRequest(Map<String, Object> input, Context context) {
		String path = (String) input.get("path");
		Map<String, String> queryStringParameters = (Map<String, String>) input.get("queryStringParameters");
		Map<String, String> headersParameters = (Map<String, String>) input.get("headers");

		try {
			if (!HTTP_ROUTES.contains(path)) {
				return handleDefault();
			}

            long startTime;
            ResultSet resultSet;
            try (PreparedStatement statement = switch (path) {
                case "/users/login" -> handleUserLogin(headersParameters);
                case "/users/register" -> handleUserRegister(headersParameters);
                case "/work_groups/create" -> handleWorkGroupCreate(headersParameters);
                case "items/create" -> handleItemCreate(headersParameters);
                case "items/get_one" -> handleItemGetOne(headersParameters);
                case "items/get_all" -> handleItemGetAll(headersParameters);
                case "items/search" -> handleItemSearch(headersParameters);
                case "items/edit" -> handleItemEdit(headersParameters);
                case "items/delete" -> handleItemDelete(headersParameters);
                default -> null;
            }) {

				if (statement == null) {
					return ApiGatewayResponse.builder().setStatusCode(400).build();
				}

				startTime = System.nanoTime();

				resultSet = statement.executeQuery();

				long timeMilliseconds = (System.nanoTime() - startTime) / 1000000;
				ArrayList<Object[]> results = new ArrayList<>();

				while (resultSet.next()) {
					results.add(new Object[]{resultSet.getObject(1), resultSet.getObject(2)});
				}

				return ApiGatewayResponse.builder()
						.setStatusCode(200)
						.setObjectBody(new Response(results, timeMilliseconds))
						.setHeaders(HEADERS).build();
			}
		} catch (Exception e) {
			LOG.error(e);
			return ApiGatewayResponse.builder().setStatusCode(500).build();
		}
	}
}

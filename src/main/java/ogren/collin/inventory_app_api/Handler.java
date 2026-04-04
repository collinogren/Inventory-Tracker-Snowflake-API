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
				where username = 'test'
				and password_hash = 'test';""";

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

	@Override
	@SuppressWarnings("unchecked")
	public ApiGatewayResponse handleRequest(Map<String, Object> input, Context context) {
		String path = (String) input.get("path");
		Map<String, String> queryStringParameters = (Map<String, String>) input.get("queryStringParameters");
		Map<String, String> headersParameters = (Map<String, String>) input.get("headers");

		try {
			PreparedStatement statement = null;
			Connection connection;
			String username;
			String password;
			String passwordHash;
			int workGroupID;
			String itemIDString;
			int itemID;
			String itemName;
			String itemQuantityString;
			int itemQuantity;
			String workGroupIDString;

			switch (path) {
				case "/users/login":
					if (headersParameters == null) {
						handleBadRequest();
						break;
					}

					username = headersParameters.get("username");
					password = headersParameters.get("password");

					if (username == null || password == null) {
						handleBadRequest();
						break;
					}

					passwordHash = Arrays.toString(messageDigest.digest(password.getBytes(StandardCharsets.UTF_8)));

					connection = Connector.connect();
					statement = userLoginPreparedStatement(username, passwordHash, connection);
					break;
				case "/users/register":
					if (headersParameters == null) {
						handleBadRequest();
						break;
					}

					username = headersParameters.get("username");
					password = headersParameters.get("password");
					workGroupIDString = headersParameters.get("workGroupID");

					if (username == null || password == null) {
						handleBadRequest();
						break;
					}

					try {
						workGroupID = Integer.parseInt(workGroupIDString);
					} catch (NumberFormatException _) {
						handleBadRequest();
						break;
					}

					passwordHash = Arrays.toString(messageDigest.digest(password.getBytes(StandardCharsets.UTF_8)));

					connection = Connector.connect();
					statement = userRegisterPreparedStatement(username, passwordHash, workGroupID,connection);
					break;
				case "/work_groups/create":
					if (headersParameters == null) {
						handleBadRequest();
						break;
					}

					String workGroupName = headersParameters.get("workGroupName");
					String joinPassword = headersParameters.get("joinPassword");
					String adminPassword = headersParameters.get("adminPassword");

					if (workGroupName == null || joinPassword == null || adminPassword == null) {
						handleBadRequest();
						break;
					}

					String joinPasswordHash = Arrays.toString(messageDigest.digest(joinPassword.getBytes(StandardCharsets.UTF_8)));
					String adminPasswordHash = Arrays.toString(messageDigest.digest(adminPassword.getBytes(StandardCharsets.UTF_8)));

					connection = Connector.connect();
					statement = workGroupCreatePreparedStatement(workGroupName, joinPasswordHash, adminPasswordHash, connection);
					break;
				case "items/create":
					itemName = headersParameters.get("itemName");
					itemQuantityString = headersParameters.get("itemQuantity");
					workGroupIDString = headersParameters.get("workGroupID");

					try {
						itemQuantity = Integer.parseInt(itemQuantityString);
						workGroupID = Integer.parseInt(workGroupIDString);
					} catch (NumberFormatException _) {
						handleBadRequest();
						break;
					}

					connection = Connector.connect();
					statement = itemCreatePreparedStatement(itemName, itemQuantity, workGroupID, connection);
					break;
				case "items/get_one":
					itemIDString = headersParameters.get("itemID");
					workGroupIDString = headersParameters.get("workGroupID");

					if (itemIDString == null || workGroupIDString == null) {
						handleBadRequest();
						break;
					}

					try {
						itemID = Integer.parseInt(itemIDString);
						workGroupID = Integer.parseInt(workGroupIDString);
					} catch (NumberFormatException _) {
						handleBadRequest();
						break;
					}

					connection = Connector.connect();
					statement = itemGetOnePreparedStatement(itemID, workGroupID, connection);
					break;
				case "items/get_all":
					workGroupIDString = headersParameters.get("workGroupID");

					if (workGroupIDString == null) {
						handleBadRequest();
						break;
					}

					try {
						workGroupID = Integer.parseInt(workGroupIDString);
					} catch (NumberFormatException _) {
						handleBadRequest();
						break;
					}
					connection = Connector.connect();
					statement = itemGetAllPreparedStatement(workGroupID, connection);
					break;
				case "items/search":
					itemName = headersParameters.get("itemName");
					workGroupIDString = headersParameters.get("workGroupID");

					if (itemName == null || workGroupIDString == null) {
						handleBadRequest();
						break;
					}

					try {
						workGroupID = Integer.parseInt(workGroupIDString);
					} catch (NumberFormatException _) {
						handleBadRequest();
						break;
					}
					connection = Connector.connect();

					if (itemName.isEmpty()) {
						statement = itemGetAllPreparedStatement(workGroupID, connection);
						break;
					}

					connection = Connector.connect();
					statement = itemSearchPreparedStatement(itemName, workGroupID, connection);
					break;
				case "items/edit":
					itemName = headersParameters.get("itemName");
					itemQuantityString = headersParameters.get("itemQuantity");
					itemIDString = headersParameters.get("itemID");
					workGroupIDString = headersParameters.get("workGroupID");

					try {
						itemQuantity = Integer.parseInt(itemQuantityString);
						itemID = Integer.parseInt(itemIDString);
						workGroupID = Integer.parseInt(workGroupIDString);
					} catch (NumberFormatException _) {
						handleBadRequest();
						break;
					}

					connection = Connector.connect();
					statement = itemEditPreparedStatement(itemName, itemQuantity, itemID, workGroupID, connection);
					break;
				case "items/delete":
					itemIDString = headersParameters.get("itemID");
					workGroupIDString = headersParameters.get("workGroupID");

					try {
						itemID = Integer.parseInt(itemIDString);
						workGroupID = Integer.parseInt(workGroupIDString);
					} catch (NumberFormatException _) {
						handleBadRequest();
						break;
					}

					connection = Connector.connect();
					statement = itemDeletePreparedStatement(itemID, workGroupID, connection);
					break;
				default:
					return handleDefault();
			}

			long startTime = System.nanoTime();

			ResultSet resultSet;
			if (statement == null) {
				return ApiGatewayResponse.builder().setStatusCode(400).build();
			} else {
				resultSet = statement.executeQuery();
			}

			long timeMilliseconds = (System.nanoTime() - startTime) / 1000000;
			ArrayList<Object[]> results = new ArrayList<>();

			while (resultSet.next()) {
				results.add(new Object[] { resultSet.getObject(1), resultSet.getObject(2) });
			}

			return ApiGatewayResponse.builder()
					.setStatusCode(200)
					.setObjectBody(new Response(results, timeMilliseconds))
					.setHeaders(HEADERS).build();
		} catch (Exception e) {
			LOG.error(e);
			return ApiGatewayResponse.builder().setStatusCode(500).build();
		}
	}
}

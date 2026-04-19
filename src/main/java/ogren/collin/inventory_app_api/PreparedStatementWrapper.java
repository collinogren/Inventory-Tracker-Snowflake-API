package ogren.collin.inventory_app_api;

import java.sql.PreparedStatement;

public record PreparedStatementWrapper<T>(PreparedStatement preparedStatement, Class<T> expectedType) implements AutoCloseable {
    @Override
    public void close() throws Exception {
        preparedStatement.close();
    }
}

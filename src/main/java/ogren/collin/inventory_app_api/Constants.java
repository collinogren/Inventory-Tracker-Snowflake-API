package ogren.collin.inventory_app_api;

import java.util.Set;

public class Constants {
    // Users
    public static final String USER_ID = "userID";
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";

    // Items
    public static final String ITEM_ID = "itemID";
    public static final String ITEM_NAME = "itemName";
    public static final String ITEM_QUANTITY = "itemQuantity";

    // Routes
    public static final String USERS_LOGIN = "/users/login";
    public static final String USERS_REGISTER = "/users/register";
    public static final String WORK_GROUPS_CREATE = "/work_groups/create";
    public static final String ITEMS_CREATE = "/items/create";
    public static final String ITEMS_GET_ONE = "/items/get_one";
    public static final String ITEMS_GET_ALL = "/items/get_all";
    public static final String ITEMS_SEARCH = "/items/search";
    public static final String ITEMS_EDIT = "/items/edit";
    public static final String ITEMS_DELETE = "/items/delete";
    public static final Set<String> HTTP_ROUTES = Set.of(
            USERS_LOGIN,
            USERS_REGISTER,
            WORK_GROUPS_CREATE,
            ITEMS_CREATE,
            ITEMS_GET_ONE,
            ITEMS_GET_ALL,
            ITEMS_SEARCH,
            ITEMS_EDIT,
            ITEMS_DELETE
    );
}

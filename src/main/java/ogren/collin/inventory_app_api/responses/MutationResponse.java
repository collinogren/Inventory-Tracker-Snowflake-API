package ogren.collin.inventory_app_api.responses;

public class MutationResponse extends AResponse<Integer> {

    public MutationResponse(int rowsAffected) {
        super(rowsAffected);
    }
}

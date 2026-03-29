package pt.unl.fct.di.adc.firstwebapp.util;

public class ErrorResponse {
    public String status;
    public String data;
    public ErrorResponse(String code, String msg) {
        this.status = code;
        this.data = msg;
    }
}

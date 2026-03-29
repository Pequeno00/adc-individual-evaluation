package pt.unl.fct.di.adc.firstwebapp.util;

public class SuccessResponse {
    public String status = "success";
    public Object data;
    public SuccessResponse(Object data) { this.data = data; }
}

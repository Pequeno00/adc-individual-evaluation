package pt.unl.fct.di.adc.firstwebapp.util;

public class RegisterData {
	
	public String username;
	public String password;
	public String confirmation;
    public String role;
    public String phone;
    public String address;
	
	
	public RegisterData() {
		
	}
	
	public RegisterData(String username, String password, String confirmation, String email, String name, String role, String phone, String address) {
		this.username = username;
		this.password = password;
		this.confirmation = confirmation;
        this.role = role;
        this.phone = phone;
        this.address = address;
	}
	
	private boolean nonEmptyOrBlankField(String field) {
		return field != null && !field.isBlank();
	}
	
	public boolean validRegistration() {
		
		 	
		return nonEmptyOrBlankField(username) &&
			   nonEmptyOrBlankField(password) &&
                nonEmptyOrBlankField(role) &&
                nonEmptyOrBlankField(phone) &&
                nonEmptyOrBlankField(address) &&
                username.contains("@") &&
			   password.equals(confirmation) &&
                isValidRole(role);
	}

    public boolean isValidRole(String role){
        return role.equals("ADMIN") || role.equals("USER") || role.equals("BOFFICER");
    }
}
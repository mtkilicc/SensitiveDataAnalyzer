package burp;

public class IssueList {
	
	String name;
	String detail;
	int severity;
	String regex;
	
	public IssueList(String name, String detail, int severity, String regex) {
		this.name = name;
		this.detail = detail;
		this.severity = severity;
		this.regex = regex;
		
	}

	public String getName() {
		return name;
	}

	public String getDetail() {
		return detail;
	}

	public int getSeverity() {
		return severity;
	}
	
	public String getRegex() {
		return regex;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setDetail(String detail) {
		this.detail = detail;
	}

	public void setSeverity(int severity) {
		this.severity = severity;
	}
	
	public void setRegex(String regex) {
		this.regex = regex;
	}
    

}

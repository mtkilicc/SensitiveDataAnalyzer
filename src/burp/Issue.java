package burp;

import java.util.ArrayList;
import java.util.List;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Scanner;

public class Issue {
	
	String name;
	String description;
	String severity;
	String regex;
	String cofidence;
	String payload;
	
	
	public Issue(String payload, String regex, String name, String description, String severity, String cofidence) {
		this.name = name;
		this.description = description;
		this.severity = severity;
		this.regex = regex;
		this.cofidence = cofidence;
		this.payload = payload;
		
	}

	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	public String getSeverity() {
		return severity;
	}
	
	public String getRegex() {
		return regex;
	}
	
	public String getCofidence() {
		return cofidence;
	}
	
	public String getPayload() {
		return payload;
	}
	
	public void setPayload(String payload) {
		this.payload = payload;
	}
	
	public void setCofidence(String cofidence) {
		this.cofidence = cofidence;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public void setSeverity(String severity) {
		this.severity = severity;
	}
	
	public void setRegex(String regex) {
		this.regex = regex;
	}
    

}

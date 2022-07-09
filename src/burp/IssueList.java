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

public class IssueList {
	
	String name;
	String detail;
	int severity;
	String regex;
	String scanType;
	
	public IssueList() {
		
	}
	
	public IssueList(String name, String detail, int severity, String regex, String scanType) {
		this.name = name;
		this.detail = detail;
		this.severity = severity;
		this.regex = regex;
		this.scanType = scanType;
		
	}
	
	public List<IssueList> generateIssue(String fileName) throws IOException{
		
		List<IssueList> listIssues = new ArrayList<>();
	        File myObj = new File(fileName);
	        Scanner myReader = new Scanner(myObj);
	        while (myReader.hasNextLine()) {	          
	          String issue = myReader.nextLine();
		      String[] issueArray = issue.split(";");
		      if (issueArray.length == 5) {
		    	  listIssues.add(new IssueList(issueArray[0],issueArray[1],Integer.valueOf(issueArray[2]),issueArray[3],issueArray[4]));
		      }
	        }
	        myReader.close();
		return listIssues;
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
	
	public String getScanType() {
		return scanType;
	}
	
	public void setScanType(String scanType) {
		this.scanType = scanType;
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

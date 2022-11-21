package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class StringUtils {
	/*
	 General Strings 
	 */
	public String userDir = System.getProperty("user.dir");
	public String dbName = "storage.db";
	public String fileName = "/issueList.json";
	public String createTable = "CREATE TABLE IF NOT EXISTS issues(scantype TEXT NOT NULL,payload TEXT NOT NULL,regex TEXT NOT NULL,name TEXT NOT NULL UNIQUE,description TEXT NOT NULL,severity TEXT NOT NULL,confidence TEXT NOT NULL);";
	public String addIssue = "INSERT INTO issues VALUES(_replace_);";
	public String checkName =  "SELECT name FROM issues WHERE name=\"_replace_\";";
	public String removeIssues = "DROP TABLE IF EXISTS issues;";
	public String getPassiveIssues = "SELECT * FROM issues WHERE scantype=\"Passive\"";
	public String getActiveIssues = "SELECT * FROM issues WHERE scantype=\"Active\"";
	public String [] jsonVariables = {"ScanType", "Payload", "Regex", "Name", "Description", "Severity", "Confidence"};
	/*
	 Info Strings 
	 */
	public String createAutoInfo = "storage.db has created.\nIssues has inserted in to the db.\nIssue's List has created.\n\nReady to running...";
	public String createAutoHeader = "Create Auto: ";
	public String createDBInfo = "storage.db has created.\n\nNext step is 'Load Issue's List or Select File'...";
	public String createDBHeader = "Create DB";
	public String loadIssueInfo = "IssueList.json has loaded.\n\nNext step is 'Generate Isssue's List'...";
	public String loadIssueHeader = "Load Issue";
	public String selectFileInfo = "Selected file has loaded.\n\nNext step is 'Generate Isssue's List'...\n\n File Path: ";
	public String selectFileHeader = "Select File";
	public String generateIssueInfo = "Issue's Lists have generated.\n\nReady to running...";
	public String generateIssueHeader = "Generate Issue's List";
	public String removeIssueInfo = "Issue's Lists have removed.\n\nNext step is 'Load Issue's List or Select File'...";
	public String removeIssueHeader = "Remove Issues from DB";
	public String showIssueInfo = "DB Informations:\nPassive size: %s \nActive size: %s\n\nVariable Information:\nPassive size: %s\nActive Size: %s";
	public String showIssueHeader = "Show Issues's Information";
	/*
	 Error Strings 
	 */
	public String generalError = "There is an error, details:\n";
	public String errorDuplicateIssueName = "Your issue name insterted before, check issue name.";
	public String errorEmptyIssueList = "Issue List couldn't create. Your regexList.json may be empty or not inclued valid context.";
	/*
	 * Name of UI elements
	 */
	public String btnCreateAuto = "Create Automatic";
	public String btnCreateDB = "Create DB";
	public String btnLoadIssue = "Load Issue";
	public String btnSelectFile = "Select File";
	public String btnGenerateIssue = "Generate Issue's List";
	public String btnRemoveIssues = "Remove Issues from DB";
	public String btnShowIssues = "Show Issues Information";
	
	
	public String createDescriptionIssue(List<String> matchArray, String description) {
		String result = "<br/> <br/> <b>Maches Details is:</b> <ul> ";
		for (int i = 0; i < matchArray.size(); i++) {
			result = result + "<li>" + matchArray.get(i).replaceAll("<","&lt;").replaceAll(">","&gt;") + "</li>"; 
		}
		result = result + "</ul>";
		result = result + "<br/><b>It's Description:</b>" + description;
		return result;
	}
	
	
	public List<List> checkMatches(String response, String[] regexes) {
		List<List> listOfMixedTypes = new ArrayList<>();
		List<String> listOfStrings = new ArrayList<>();
		List<int[]> matches = new ArrayList<>();
		for (int i = 0; i < regexes.length; i++) {
			Pattern pattern = Pattern.compile(regexes[i]);
			Matcher matcher = pattern.matcher(response);
			while (matcher.find()) {
	            matches.add(new int[]{matcher.start(0), matcher.end(0)});
	            listOfStrings.add(response.substring(matcher.start(0),matcher.end(0)));
	        }
		}
        listOfMixedTypes.add(listOfStrings);
        listOfMixedTypes.add(matches);
		return listOfMixedTypes;
	}
	
}

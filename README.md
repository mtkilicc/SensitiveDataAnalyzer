# SensitiveDataAnalyzer
Burp Extention

The extention ensure to anaylze respose with regex that included issueList.json for find information.

The issueList.json location must locate BurpSuite.jar file location. While the extention is loading, if the issueList.json location is wrong, the extention give to error that include which file path is nessacery.

##  Usage

Before running this extension, you may need to some of jar files that inside of the libs directory.

* Download that jar files in the same directory
* Select that directory from Burp Suite -> Extender -> Options -> Java Environment

And also If you want use Create Automatic setting, you need to download IssueList.json file and copy BurpSuite.jar file location.

After that you can install/load Sensitive Data Analyzer.

**You can find some new features on the extention tab that named "Sensitive Data Analyzer".**
-  Create Automatic -> This button ensure to;
    *  creation DB
    *  inserting data into the db from issueList.json file(the file must be same located with BurpSuite.jar)
    *  generating issueList variables for prepare to scanning
    
-  Create DB -> This button ensure to;
    *  creation DB
    
-  Load Issue -> This button ensure to;
    *  inserting data into the db from issueList.json file(the file must be same located with BurpSuite.jar)
    
-  Select File -> This button ensure to;
    *  inserting data into the db from selected file
    
-  Generate- Issue's List -> This button ensure to;
    *  generating issueList variables for prepare to scanning
    
-  Remove Issues from DB -> This button ensure to;
    *  Remove all issues from db.
    
-  Show Issue Information -> This button ensure to;
    *  Showing the issues' information which located in the db and variable.
    
 ## How It's Work
 
 **Passive Scan:**
   *  The extension just runs in only scope. The issues which scan type is Passive, search the response and if the regex matches any data, the issue will create by extension. 
   
 **Active Scan:**
   *  The extension just runs in only scope. The issues which scan type is Active, send the payload to server and after that search the response and if the regex matches any data, the issue will create by extension. 
 
 ## Json File Fields Descripton
 
 ```
{
"Confidence": "Certain", // The issue confidence level. Expected values are "Certain", "Firm" or "Tentative".
"Description": "description", // The issue Description area. Expected value detailed information is related to finding
"Name": "name", // The name of the issue type (e.g. "SQL injection"), must be unique, you cannot add different issue with same name
"Payload": "payload", // If you want use active scan, you can add some of payload or payloads. If you want to add multiple payload, you need add _split_ between all payloads.
"Regex": "regex", // If you want use active/passive scan, you can add some of regex. If you want to add multiple regex, you need add _split_ between all regex.
"ScanType": "Passive", // The issue using on active on passive scan. Expected values are "Passive" or "Active".
"Severity": "Low" // issue severity level. Expected values are "High", "Medium", "Low", "Information" or "False positive".
}
 ```

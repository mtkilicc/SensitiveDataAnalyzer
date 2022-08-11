package burp;

import java.net.URL;

public class CustomScanIssue implements IScanIssue{

	private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;
    private String confidence;

    public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity, String confidence) {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
        this.confidence = confidence;
    }

	@Override
	public URL getUrl() {
		// TODO Auto-generated method stub
		return this.url;
	}

	@Override
	public String getIssueName() {
		// TODO Auto-generated method stub
		return this.name;
	}

	@Override
	public int getIssueType() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public String getSeverity() {
		// TODO Auto-generated method stub
		return this.severity;
	}

	@Override
	public String getConfidence() {
		// TODO Auto-generated method stub
		return this.confidence;
	}

	@Override
	public String getIssueBackground() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getRemediationBackground() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getIssueDetail() {
		// TODO Auto-generated method stub
		return this.detail;
	}

	@Override
	public String getRemediationDetail() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		// TODO Auto-generated method stub
		return this.httpMessages;
	}

	@Override
	public IHttpService getHttpService() {
		// TODO Auto-generated method stub
		return this.httpService;
	}
	
}

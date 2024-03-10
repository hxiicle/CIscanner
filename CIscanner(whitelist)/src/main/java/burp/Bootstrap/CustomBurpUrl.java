package burp.Bootstrap;

import java.net.URL;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.List;

import burp.*;

public class CustomBurpUrl {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    public PrintWriter stderr;

    private IHttpRequestResponse requestResponse;



    public CustomBurpUrl(IBurpExtenderCallbacks callbacks, IHttpRequestResponse requestResponse) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        this.requestResponse = requestResponse;


    }

    public IHttpRequestResponse requestResponse() {
        return this.requestResponse;
    }

    /**
     * 获取-请求头
     *
     * @return
     */
    public String getRequestMethod() {
        return this.helpers.analyzeRequest(this.requestResponse).getMethod();
    }

    /**
     * 获取-请求头
     *
     * @return
     */
    public List<String> getRequestHeader() {
        return this.helpers.analyzeRequest(this.requestResponse).getHeaders();
    }

    /**
     * 获取-请求体
     *
     * @return
     */
    public String getRequestBody() {
        byte[] request = this.requestResponse.getRequest();
        // 获取请求信息对象
        IRequestInfo requestInfo = this.helpers.analyzeRequest(this.requestResponse);
        // 获取请求体的偏移量
        int bodyOffset = requestInfo.getBodyOffset();
        // 获取请求体的内容
        byte[] requestBody = Arrays.copyOfRange(request, bodyOffset, request.length);
        // 将请求体内容转换为字符串
        String requestBodyString = new String(requestBody);
        if (requestBodyString.isEmpty()) {
            return "False";
        } else {
            return requestBodyString;
        }
    }



    /**
     * 获取-请求协议
     *
     * @return
     */
    public String getRequestProtocol() {
        return this.requestResponse.getHttpService().getProtocol();
    }

    /**
     * 获取-请求主机
     *
     * @return
     */
    public String getRequestHost() {
        return this.requestResponse.getHttpService().getHost();
    }

    /**
     * 获取-请求端口
     *
     * @return
     */
    public int getRequestPort() {
        return this.requestResponse.getHttpService().getPort();
    }

    /**
     * 获取-请求路径
     *
     * @return
     */
    public String getRequestPath() {
        return this.helpers.analyzeRequest(this.requestResponse).getUrl().getPath();
    }

    /**
     * 获取-请求URL参数
     *
     * @return
     */
    public String getRequestQuery() {
        return this.helpers.analyzeRequest(this.requestResponse).getUrl().getQuery();
    }

    /**
     * 获取-请求域名名称
     *
     * @return
     */
    public String getRequestDomainName() {
        if (this.getRequestPort() == 80 || this.getRequestPort() == 443) {
            return this.getRequestProtocol() + "://" + this.getRequestHost();
        } else {
            return this.getRequestProtocol() + "://" + this.getRequestHost() + ":" + this.getRequestPort();
        }
    }

    /**
     * 获取-获取http请求url
     *
     * @return
     */
    public URL getHttpRequestUrl() {
        try {
            if (this.getRequestQuery() == null) {
                return new URL(this.getRequestDomainName() + this.getRequestPath());
            } else {
                return new URL(this.getRequestDomainName() + this.getRequestPath() + "?" + this.getRequestQuery());
            }
        } catch (MalformedURLException e) {
            e.printStackTrace(this.stderr);
        }
        return null;
    }
}
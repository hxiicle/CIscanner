package burp;

import java.io.PrintWriter;

import java.util.*;
import java.util.regex.Pattern;

import burp.Bootstrap.CustomBurpUrl;
import org.apache.commons.lang3.RandomStringUtils;
import burp.Application.GetDnsLogThread;

public class BurpExtender implements IBurpExtender, IScannerCheck, IExtensionStateListener {
    public static String NAME = "CIscanner";
    public static String VERSION = "2.0.0";
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    private PrintWriter stdout;
    private CITab citab;
    private PrintWriter stderr;

    private GetDnsLogThread getDnsLogThread;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // 标签界面
        this.citab = new CITab(callbacks, NAME);

        // 设置插件名称
        callbacks.setExtensionName(NAME);
        // 基本信息输出
        this.stdout.println(basicInformationOutput());
        callbacks.registerScannerCheck(this);
        callbacks.registerExtensionStateListener(this);
    }

    /**
     * 基本信息输出
     */
    private static String basicInformationOutput() {
        String title = ""
                +"\n[-]Plugin Name: " + NAME
                +"\n[-]Version: "  + VERSION
                +"\n[-]Author: hxiicle"
                +"\n[-]Statement: Only allowed for cyber security research!Prohibited for illegal purposes!"
                +"\n\n*** Please activate the plug-in before use";
        return title;
    }

    // 卸载插件时执行的命令
    public void extensionUnloaded() {
        this.citab.setStartBoxFalse();
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // 判断是否开启插件
        if(!this.citab.isStart()) {
            return null;
        }

        // 基础url解析
        CustomBurpUrl baseBurpUrl = new CustomBurpUrl(this.callbacks, baseRequestResponse);

        // 判断当前请求后缀,是否为url黑名单后缀
        if (this.isUrlBlackListSuffix(baseBurpUrl)) {
            return null;
        }

        // 目标域名名单
        String targetListString = this.citab.getTargetList();
        List<String> domainNameWhitelist = Arrays.asList(targetListString.split("\n"));
        if (domainNameWhitelist != null && domainNameWhitelist.size() >= 1) {
            if (!isMatchDomainName(baseBurpUrl.getRequestHost(), domainNameWhitelist)) {
                return null;
            }
        }

        String method = baseBurpUrl.getRequestMethod();
        List<String> header = baseBurpUrl.getRequestHeader();
        // 获取参数
        String params = this.getParamString(method, header, baseBurpUrl);
        //this.stdout.println("params:" + params);
        // 判断是否有参数
        if (params.equals("False")) {
            return null;
        }

        String[] paramsArrays = params.split("&");

        Map<Integer, List<String>> map = new HashMap<>();

        byte[] request = baseRequestResponse.getRequest();

        IHttpService httpService = baseRequestResponse.getHttpService();

        // 获取payload列表
        String payloadString = this.citab.getPayload();
        List<String> payloadList = Arrays.asList(payloadString.split("\n"));
        for (String payload : payloadList) {
            List<String> subDnsServerList = new ArrayList<>();
            for (String parameter : paramsArrays) {
                String[] parts = parameter.split("=");
                if (parts.length >= 1) {
                    String name = parts[0];
                    String subDnsServer = getSubDnsServer(this.citab.getDnsServer());
                    subDnsServerList.add(subDnsServer);
                    // 将payload和dnsserver拼接，如果没有{DNSSERVER}则拼接到最后
                    String totalPayload;
                    if (payload.contains("{DNSSERVER}")) {
                        totalPayload = payload.replaceAll(Pattern.quote("{DNSSERVER}"),subDnsServer);
                    } else {
                        totalPayload = payload + subDnsServer;
                    }
                    // 替换参数的值
                    if (method.equals("GET")) {
                        // 替换参数的值
                        IParameter buildUrlParameter = this.helpers.buildParameter(name, totalPayload, IParameter.PARAM_URL);
                        // 生成新的请求包
                        request = this.helpers.updateParameter(request, buildUrlParameter);
                    } else {
                        // 替换参数的值
                        IParameter buildUrlParameter = this.helpers.buildParameter(name, totalPayload, IParameter.PARAM_BODY);
                        // 生成新的请求包
                        request = this.helpers.updateParameter(request, buildUrlParameter);
                    }
                }
            }
            // 发送更新后的请求包
            IHttpRequestResponse newRequestResponse = this.callbacks.makeHttpRequest(httpService, request);
            // 新的url解析
            CustomBurpUrl newBurpUrl = new CustomBurpUrl(this.callbacks, newRequestResponse);

            int ciTagId = this.citab.add(
                    method,
                    newBurpUrl.getHttpRequestUrl().toString(),
                    this.helpers.analyzeResponse(newRequestResponse.getResponse()).getStatusCode() + "",
                    "waiting for test results",
                    newRequestResponse
            );

            map.put(ciTagId, subDnsServerList);
        }

        // 获取带token的URL
        String tokenUrl = this.citab.getToken();
        int threadInt = this.citab.getThread();
        //this.stdout.println("tokenUrl:" + tokenUrl);
        //this.stdout.println("threadInt:" + threadInt);

        //this.stdout.println("map:" + map);
        synchronized (this.citab.getUdatas()) {
            // 线程开始
            try {
                this.getDnsLogThread = new GetDnsLogThread();
                List<String> isFindStringList = this.getDnsLogThread.GetDnsLogThreadString(this.callbacks, map, this.citab.isStart(), tokenUrl, threadInt);
                for (String isFindString : isFindStringList) {
                    if (isFindString.contains("Find")) {
                        String issue = "Danger";
                        //this.stdout.println("id:" + isFindString);
                        this.citab.update(Integer.parseInt(isFindString.replaceAll("Find", "")), issue);
                    } else {
                        String issue = "";
                        //this.stdout.println("id:" + isFindString);
                        this.citab.update(Integer.parseInt(isFindString.replaceAll("No", "")), issue);
                    }
                }
            } catch (Exception e) {
                this.stderr.println(e);
                this.stdout.println("*** 大概率是你的API响应不过来了 ***");
            }
        }

        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }

    /**
     * 判断是否查找的到指定的域名
     *
     * @param domainName     需匹配的域名
     * @param domainNameList 待匹配的域名列表
     * @return
     */
    private static Boolean isMatchDomainName(String domainName, List<String> domainNameList) {
        domainName = domainName.trim();

        if (domainName.length() <= 0) {
            return false;
        }

        if (domainNameList == null || domainNameList.size() <= 0) {
            return false;
        }

        if (domainName.contains(":")) {
            domainName = domainName.substring(0, domainName.indexOf(":"));
        }

        String reverseDomainName = new StringBuffer(domainName).reverse().toString();

        for (String domainName2 : domainNameList) {
            domainName2 = domainName2.trim();

            if (domainName2.length() <= 0) {
                continue;
            }

            if (domainName2.contains(":")) {
                domainName2 = domainName2.substring(0, domainName2.indexOf(":"));
            }

            String reverseDomainName2 = new StringBuffer(domainName2).reverse().toString();

            if (domainName.equals(domainName2)) {
                return true;
            }

            if (reverseDomainName.contains(".") && reverseDomainName2.contains(".")) {
                List<String> splitDomainName = new ArrayList<String>(Arrays.asList(reverseDomainName.split("[.]")));

                List<String> splitDomainName2 = new ArrayList<String>(Arrays.asList(reverseDomainName2.split("[.]")));

                if (splitDomainName.size() <= 0 || splitDomainName2.size() <= 0) {
                    continue;
                }

                if (splitDomainName.size() < splitDomainName2.size()) {
                    for (int i = splitDomainName.size(); i < splitDomainName2.size(); i++) {
                        splitDomainName.add("*");
                    }
                }

                if (splitDomainName.size() > splitDomainName2.size()) {
                    for (int i = splitDomainName2.size(); i < splitDomainName.size(); i++) {
                        splitDomainName2.add("*");
                    }
                }

                int ii = 0;
                for (int i = 0; i < splitDomainName.size(); i++) {
                    if (splitDomainName2.get(i).equals("*")) {
                        ii = ii + 1;
                    } else if (splitDomainName.get(i).equals(splitDomainName2.get(i))) {
                        ii = ii + 1;
                    }
                }

                if (ii == splitDomainName.size()) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 判断是否url黑名单后缀
     * 大小写不区分
     * 是 = true, 否 = false
     *
     * @param burpUrl
     * @return
     */
    private boolean isUrlBlackListSuffix(CustomBurpUrl burpUrl) {

        String noParameterUrl = burpUrl.getHttpRequestUrl().toString().split("\\?")[0];
        String urlSuffix = noParameterUrl.substring(noParameterUrl.lastIndexOf(".") + 1);

        List<String> suffixList = Arrays.asList( "3g2", "3gp", "7z", "aac", "abw",
                "aif", "aifc", "aiff", "arc", "au", "avi", "azw", "bin",
                "bmp", "bz", "bz2", "cmx", "cod", "csh", "css", "csv",
                "doc", "docx", "eot", "epub", "gif", "gz", "ico", "ics",
                "ief", "jar", "jfif", "jpe", "jpeg", "jpg", "m3u", "mid",
                "midi", "mjs", "mp2", "mp3", "mpa", "mpe", "mpeg", "mpg",
                "mpkg", "mpp", "mpv2", "odp", "ods", "odt", "oga", "ogv",
                "ogx", "otf", "pbm", "pdf", "pgm", "png", "pnm", "ppm",
                "ppt", "pptx", "ra", "ram", "rar", "ras", "rgb", "rmi",
                "rtf", "snd", "svg", "swf", "tar", "tif", "tiff", "ttf",
                "vsd", "wav", "weba", "webm", "webp", "woff", "woff2",
                "xbm", "xls", "xlsx", "xpm", "xul", "xwd", "zip", "js",
                "wmv", "asf", "asx", "rm", "rmvb", "mp4", "mov", "m4v",
                "dat", "mkv", "flv", "vob", "txt", "img" );

        for (String s : suffixList) {
            if (s.toLowerCase().equals(urlSuffix.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    /**
     * 获取参数
     */
    private String getParamString(String method,
                                List<String> header,
                                CustomBurpUrl burpUrl) {
        String urlQuery = burpUrl.getRequestQuery();
        String headerString = String.join("!", header);

        if (method.equals("GET")) {
            if (urlQuery != null && !urlQuery.isEmpty()) {
                return urlQuery;
            }
            else {
                return "False";
            }
        } else if (headerString.contains("application/x-www-form-urlencoded")) {
            String requestBody = burpUrl.getRequestBody();
            return requestBody;
        } else {
            return "False";
        }
    }

    // 生成随机字符串并拼接 DnsServer
    private String getSubDnsServer(String dnsServer) {
        String randomStr = RandomStringUtils.randomAlphanumeric(15);
        return "I.m.scanning." + randomStr + "." + dnsServer;
    }

}

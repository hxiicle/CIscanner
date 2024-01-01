package burp;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.jetbrains.annotations.NotNull;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.List;
import java.util.*;
import java.io.IOException;
import java.net.URL;


public class PassiveScan implements IScannerCheck {
    public CITab ciTab = new CITab();
    public PrintWriter stderr = new PrintWriter(BurpExtender.callbacks.getStderr(), true);

    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // Passive Scanning 没有勾选则关闭被动扫描
        if (!CITab.DScheckBox1.isSelected()) {
            return null;
        }
        // 获取请求包
        byte[] request = baseRequestResponse.getRequest();
        // 分析请求包，方便后续提取数据
        IRequestInfo analyzedIRequestInfo = BurpExtender.helpers.analyzeRequest(request);
        String reqMethod = BurpExtender.helpers.analyzeRequest(request).getMethod();
        // 获取请求头
        List<String> request_header = analyzedIRequestInfo.getHeaders();
        // 获取请求头第一行，包含请求方法、请求uri、http版本
        String firstrequest_header = request_header.get(0);
        String[] firstheaders = firstrequest_header.split(" ");

        // uri黑名单，如果匹配到则不扫描
        List<String> blacklists = Arrays.asList( ".js" ,".jpg", ".png", ".jpeg",
                ".svg", ".mp4", ".css", ".mp3", ".ico", ".woff", ".woff2" );
        for (String black_single: blacklists) {
            if (firstheaders[1].split("\\?")[0].endsWith(black_single)) {
                return null;
            }
            break;
        }
        // 不符合黑名单中的值则不扫描
        if (!reqMethod.equals("GET")) {
            for (String request_header_single : request_header) {
                if (request_header_single.contains("Content-Type")) {
                    if (!request_header_single.contains("application/x-www-form-urlencoded")) {
                        return null;
                    }
                    break; // 找到符合条件的请求头后立即退出循环
                }
            }
        }

        // 获取请求头中 host 的值
        String request_header_host = headers_to_host(request_header);
        // 获取 Whitelist lists
        String[] Whitelist_lists = CITab.CPtextArea2.getText().split("\n");
        // host 拼接端口
        IHttpService httpService = baseRequestResponse.getHttpService();
        String host = httpService.getHost();
        host = host + ":" + httpService.getPort();
        // 遍历 Whitelist_lists 的值
        if (Whitelist_lists.length == 0) {
            for (String Whitelist_single : Whitelist_lists) {
                // 将 Whitelist_lists 中的*号去掉
                Whitelist_single = Whitelist_single.replace("*", "");
                // host 去掉端口
                String[] hostlists = host.split(":");
                // 如果与白名单内域名后缀相同，则不扫描
                if (hostlists[0].endsWith(Whitelist_single) || request_header_host.endsWith(Whitelist_single)) {
                    return null;
                }
                break;
            }
        }

        // 获取请求包中的参数
        List<IParameter> iParameterList = analyzedIRequestInfo.getParameters();
        // 用于存放url中的参数
        List<IParameter> iParameterList_Url = new ArrayList<>();
        // 用于存放body体中的参数
        List<IParameter> iParameterList_Body = new ArrayList<>();
        // 将参数分开存放
        for (IParameter iParameter : iParameterList) {
            int type = iParameter.getType();
            if(type == 0){
                iParameterList_Url.add(iParameter);
            }else if(type == 1){
                iParameterList_Body.add(iParameter);
            }
        }

        // 如果没有参数，则不扫描
        if (iParameterList_Url.isEmpty() && iParameterList_Body.isEmpty()) {
            return null;
        }

        // 获取 payload list
        String[] payload_lists = Get_Payload_List();

        // 获取填入的值
        boolean Use_Ceye = CITab.DScheckBox2.isSelected();
        String Ceye_Dns_Server = CITab.DStextField1.getText().trim();
        String Ceye_Token = CITab.DStextField2.getText().trim();
        boolean Use_Other_Dnslog = CITab.DScheckBox3.isSelected();
        String Dns_Server = CITab.DStextField3.getText().trim();
        String URL_With_Token = CITab.DStextField4.getText().trim();

        String DnsServer = "";
        String GetAPI = "";

        if (Use_Ceye) {
            DnsServer = Ceye_Dns_Server;
            GetAPI = "http://api.ceye.io/v1/records?token=" + Ceye_Token + "&type=dns&filter=";
        } else if (Use_Other_Dnslog) {
            DnsServer = Dns_Server;
            GetAPI = URL_With_Token;
        }


        PrintWriter stdout = new PrintWriter(BurpExtender.callbacks.getStdout(), true);
        // 遍历 Payload
        for (String payload_single:payload_lists) {
            // 用于储存拼接后的 DnsServer
            List<String> SubDnsServer_List = new ArrayList<>();
            // 如果有 URL 参数，则更新所有参数的值为
            if (!iParameterList_Url.isEmpty()) {
                for (IParameter iParameter : iParameterList_Url) {
                    // 获取拼接后的 DnsServer
                    String SubDnsServer = GET_SubDnsServer(DnsServer);
                    SubDnsServer_List.add(SubDnsServer);
                    // 将 Payload 和 SubDnsServer 拼接 组成完整的 Payload
                    String Total_Payload = payload_single + SubDnsServer;
                    // 替换所有参数的值
                    IParameter build_url_parameter = BurpExtender.helpers.buildParameter(iParameter.getName(), Total_Payload, IParameter.PARAM_URL);
                    // 生成新的请求包
                    request = BurpExtender.helpers.updateParameter(request, build_url_parameter);
                }
            }
            // 如果请求体有参数，则更新所有参数的值为
            if (!iParameterList_Body.isEmpty()) {
                for (IParameter iParameter : iParameterList_Body) {
                    // 获取拼接后的 DnsServer
                    String SubDnsServer = GET_SubDnsServer(DnsServer);
                    SubDnsServer_List.add(SubDnsServer);
                    // 将 Payload 和 SubDnsServer 拼接 组成完整的 Payload
                    String Total_Payload = payload_single + SubDnsServer;
                    // 替换所有参数的值
                    IParameter build_body_parameter = BurpExtender.helpers.buildParameter(iParameter.getName(), Total_Payload, IParameter.PARAM_BODY);
                    // 生成新的请求包
                    request = BurpExtender.helpers.updateParameter(request, build_body_parameter);
                }
            }

            // 发送更新后的请求包
            IHttpRequestResponse NewIHttpRequestResponse = BurpExtender.callbacks.makeHttpRequest(httpService, request);
            // 获取修改包后的响应包
            byte[] New_Response = NewIHttpRequestResponse.getResponse();
            URL url = BurpExtender.helpers.analyzeRequest(NewIHttpRequestResponse).getUrl();
            String url_string = url.toString();
            short status = BurpExtender.helpers.analyzeResponse(New_Response).getStatusCode();
            String status_string = Short.toString(status);
            String issue;

            List<String> issueList = new ArrayList<>();

            // 遍历 SubDnsServer_List，如果 DnsLog 有记录，则存在漏洞
            String responseBody = getApi(GetAPI);
            for (String subDnsServer : SubDnsServer_List) {
                if (responseBody.toLowerCase().contains(subDnsServer.toLowerCase())) {
                    issue = "Danger";
                } else {
                    issue = "css";
                }
                issueList.add(issue);
            }
            //this.ciTab = new CITab();
            if (issueList.contains("Danger")) {
                issue = "Danger";
                ciTab.add(reqMethod, url_string, status_string, issue, NewIHttpRequestResponse);
                stdout.println("\n================================================");
                stdout.println("发现漏洞！");
                stdout.println("URL是 " + url);
                stdout.println("================================================");
            } else {
                issue = "";
                this.ciTab.add(reqMethod, url_string, status_string, issue, NewIHttpRequestResponse);
                int row = this.ciTab.Udatas.size();
                // 如果 DnsLog 没有记录，则将生成的 SubDnsServer 存入文件 CIScanner_SubDomain.txt
                String commaSeparatedString = String.join(", ", SubDnsServer_List);
                String newRow = row + ": " + commaSeparatedString;
                List<String> lines = new ArrayList<>();
                // 读取文件内容并保存到列表中
                try {
                    File subDomainFile = getSubDomainFile();
                    if (getSubDomainFile().exists()) {
                        try (BufferedReader reader = new BufferedReader(new FileReader(subDomainFile))) {
                            String line;
                            while ((line = reader.readLine()) != null) {
                                if (!line.trim().isEmpty()) {
                                    lines.add(line);
                                }
                            }
                        }
                        // 检查列表中是否存在比当前行数大的行，如果存在则删除
                        lines.removeIf(existingLine -> {
                            String[] existingLine_lists = existingLine.split(": ", 2);
                            int existingRow = Integer.parseInt(existingLine_lists[0]);
                            return existingRow >= row;
                        });

                        // 将更新后的行添加到列表末尾
                        lines.add(newRow);

                        // 检查行数是否达到10，如果是，则删除前5行
                        if (lines.size() >= 10) {
                            lines.subList(0, 5).clear();
                        }
                        // 将更新后的列表写入文件
                        BufferedWriter writer = new BufferedWriter(new FileWriter(subDomainFile));
                        for (String updatedLine : lines) {
                            writer.write(updatedLine + "\n");
                        }
                        writer.close();
                    } else {
                        BufferedWriter writer = new BufferedWriter(new FileWriter(subDomainFile));
                        writer.write(newRow + "\n");
                        writer.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace(stderr);
                }

            }
            // 轮询
            getCycleAccess(GetAPI);
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

    // 获取 Payload list
    public String[] Get_Payload_List() {
        String[] payload_lists = CITab.CPtextArea1.getText().split("\n");
        return payload_lists;
    }

    // 获取请求头中的host值
    public String headers_to_host(List<String> request_header){
        for (String request_header_single : request_header){
            if (request_header_single.substring(0,5).contains("Host") || request_header_single.substring(0,5).contains("host")){
                String[] request_header_single_lists = request_header_single.split(":");
                return request_header_single_lists[1].trim();
            }
        }
        return null;
    }

    // 生成五组随机字符串并拼接 Dns Server
    public String GET_SubDnsServer(String dnsserver) {
        StringBuilder subdnsserver = new StringBuilder("I.m.coming.");
        Random random = new Random();

        for (int i = 0; i < 5; i++) {
            String random_str = generateRandomAlphanumeric(3,random);
            subdnsserver.append(random_str).append(".");
        }

        subdnsserver.append(dnsserver);
        return subdnsserver.toString();
    }

    private String generateRandomAlphanumeric(int length, Random random) {
        StringBuilder sb = new StringBuilder(length);
        String alphanumeric = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(alphanumeric.length());
            char randomChar = alphanumeric.charAt(randomIndex);
            sb.append(randomChar);
        }

        return sb.toString();
    }

    // 发送get请求，返回响应体
    public String getApi(String url) {
        OkHttpClient client = new OkHttpClient();
        String responseBody = null;

        Request request = new Request.Builder()
                .url(url)
                .get()
                .build();

        try {
            // 添加延迟
            Thread.sleep(2500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            e.printStackTrace(stderr);
        }

        try (Response response = client.newCall(request).execute()) {
            if (response.isSuccessful()) {
                responseBody = response.body().string();
            }
        } catch (IOException e) {
            e.printStackTrace(stderr);
        }
        return responseBody;
    }

    // 生成存储 SubDnsServer 的文件
    @NotNull
    public static File getSubDomainFile() {
        String os = System.getProperty("os.name").toLowerCase();
        String configFile;

        if (os.startsWith("win")) {
            configFile = "CIScanner_SubDomain.txt";
        } else {
            String jarPath = BurpExtender.callbacks.getExtensionFilename();
            String directory = new File(jarPath).getParent();
            configFile = directory + File.separator + "CIScanner_SubDomain.txt";
        }

        return new File(configFile);
    }

    // 从文件 CIScanner_SubDomain.txt 中读取数据，将数据
    public void getCycleAccess(String getapi) {
        File subDomainFile = getSubDomainFile();
        if (subDomainFile.length() == 0) {
            return;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(subDomainFile))) {
            String line;
            while ((line = reader.readLine()) != null && CITab.DScheckBox1.isSelected()) {
                String[] parts = line.split(": ");
                if (parts.length == 2) {
                    int number = Integer.parseInt(parts[0].trim());
                    String[] domains = parts[1].split(", ");

                    String responseBody = getApi(getapi);
                    for (String domain : domains) {
                        String formattedDomain = domain.trim();
                        if (responseBody.toLowerCase().contains(formattedDomain.toLowerCase())) {
                            this.ciTab.update(number-1);
                            deleteLine(getSubDomainFile().getAbsolutePath(), line);
                            return;
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace(stderr);
        }
    }

    private void deleteLine(String fileName, String lineToRemove) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(fileName));
            StringBuffer buffer = new StringBuffer();
            String line;

            while ((line = reader.readLine()) != null) {
                if (!line.trim().equals(lineToRemove)) {
                    buffer.append(line);
                    buffer.append(System.lineSeparator());
                }
            }
            reader.close();

            // 将更新后的内容写回到文件
            FileWriter writer = new FileWriter(fileName);
            writer.write(buffer.toString());
            writer.close();
        } catch (IOException e) {
            e.printStackTrace(stderr);
        }
    }

}

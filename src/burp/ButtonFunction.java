package burp;

import javax.swing.*;
import java.io.*;
import okhttp3.*;
import org.apache.commons.lang3.RandomStringUtils;

import java.util.Objects;
import java.util.regex.*;

public class ButtonFunction {
    public static PrintWriter stderr = new PrintWriter(BurpExtender.callbacks.getStderr(), true);

    /* *************************** Save Configuration *************************** */
    public static void Save_Configuration(){

        boolean Use_Ceye = CITab.DScheckBox2.isSelected();
        String Ceye_Dns_Server = CITab.DStextField1.getText().trim();
        String Ceye_Token = CITab.DStextField2.getText().trim();
        boolean Use_Other_Dnslog = CITab.DScheckBox3.isSelected();
        String Dns_Server = CITab.DStextField3.getText().trim();
        String URL_With_Token = CITab.DStextField4.getText().trim();
        String Payload = CITab.CPtextArea1.getText().trim().replace("\n","; ");
        String Whitelist = CITab.CPtextArea2.getText().trim().replace("\n","; ");
        // 用于追加配置的字符串
        String total = "";

        // 写入 Ceye 的值
        total = total +"[Ceye]" + "\n";
        String Ceye;
        if (Use_Ceye){
            Ceye = "1";
        }else{
            Ceye = "0";
        }
        total = total + "Ceye = " + Ceye + "\n";

        // 写入 Ceye Dns Server
        total = total + "Ceye Dns Server = " + Ceye_Dns_Server + "\n";

        // 写入 Ceye Token
        total = total + "Ceye Token = " + Ceye_Token + "\n";

        // Use Other Dnslog 的值
        total = total +"\n[Other Dnslog]" + "\n";
        String Other_Dnslog;
        if (Use_Other_Dnslog){
            Other_Dnslog = "1";
        }else{
            Other_Dnslog = "0";
        }
        total = total + "Other Dnslog = " + Other_Dnslog + "\n";

        // 写入 Dns Server
        total = total + "Dns Server = " + Dns_Server + "\n";

        // 写入 URL With Token
        total = total + "URL With Token = " + URL_With_Token + "\n";

        // 写入 Payload
        total = total + "\n[Payload]\nPayload = " + Payload + "\n";

        // 写入 Whitelist
        total = total + "\n[Whitelist]\nWhitelist = " + Whitelist;

        // 写入配置文件
        try (FileWriter fileWriter = new FileWriter(CITab.getConfigFile().getAbsolutePath())) {
            fileWriter.append(total);
        } catch (IOException e) {
            e.printStackTrace(stderr);
        }

        // 判断是否有未按照要求填入的值
        String Content = Check_All_Fill();

        JOptionPane.showMessageDialog(null, Content , "Save", JOptionPane.INFORMATION_MESSAGE);
    }

    // 判断是否有未按照要求填入的值
    public static String Check_All_Fill() {
        boolean Use_Ceye = CITab.DScheckBox2.isSelected();
        String Ceye_Dns_Server = CITab.DStextField1.getText().trim();
        String Ceye_Token = CITab.DStextField2.getText().trim();
        boolean Use_Other_Dnslog = CITab.DScheckBox3.isSelected();
        String Dns_Server = CITab.DStextField3.getText().trim();
        String URL_With_Token = CITab.DStextField4.getText().trim();
        String Payload = CITab.CPtextArea1.getText().trim().replace("\n","; ");
        // 提示信息
        String Content = "";
        if (!Use_Ceye && !Use_Other_Dnslog) {
            Content = "Fail!\nYou need to choose to use <Use Ceye> or <Use Other Dnslog>";
        } else if (Use_Ceye && Ceye_Dns_Server.isEmpty() && Ceye_Token.isEmpty() && Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Dns Server> , <Ceye Token> and <Payload>";
        } else if (Use_Ceye && Ceye_Dns_Server.isEmpty() && !Ceye_Token.isEmpty() && Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Dns Server> and <Payload>";
        } else if (Use_Ceye && Ceye_Dns_Server.isEmpty() && Ceye_Token.isEmpty() && !Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Dns Server> and <Ceye Token>";
        } else if (Use_Ceye && Ceye_Dns_Server.isEmpty() && !Ceye_Token.isEmpty() && !Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Dns Server>";

        } else if (Use_Ceye && !Ceye_Dns_Server.isEmpty() && Ceye_Token.isEmpty() && Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Token> and <Payload>";
        } else if (Use_Ceye && !Ceye_Dns_Server.isEmpty() && !Ceye_Token.isEmpty() && Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Payload>";
        } else if (Use_Ceye && !Ceye_Dns_Server.isEmpty() && Ceye_Token.isEmpty() && !Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Token>";
        } else if (Use_Ceye && !Ceye_Dns_Server.isEmpty() && !Ceye_Token.isEmpty() && !Payload.isEmpty()) {
            Content = "Success!";

        } else if (Use_Other_Dnslog && Dns_Server.isEmpty() && URL_With_Token.isEmpty() && Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <Dns Server> , <URL With Token> and <Payload>";
        } else if (Use_Other_Dnslog && Dns_Server.isEmpty() && !URL_With_Token.isEmpty() && Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <Dns Server> and <Payload>";
        } else if (Use_Other_Dnslog && Dns_Server.isEmpty() && URL_With_Token.isEmpty() && !Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <Dns Server> and <URL With Token>";
        } else if (Use_Other_Dnslog && Dns_Server.isEmpty() && !URL_With_Token.isEmpty() && !Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <Dns Server>";

        } else if (Use_Other_Dnslog && !Dns_Server.isEmpty() && URL_With_Token.isEmpty() && Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <URL With Token> and <Payload>";
        } else if (Use_Other_Dnslog && !Dns_Server.isEmpty() && !URL_With_Token.isEmpty() && Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <Payload>";
        } else if (Use_Other_Dnslog && !Dns_Server.isEmpty() && URL_With_Token.isEmpty() && !Payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <URL With Token>";
        } else if (Use_Other_Dnslog && !Dns_Server.isEmpty() && !URL_With_Token.isEmpty() && !Payload.isEmpty()) {
            Content = "Success!";
        }
        return Content;
    }


    /* *************************** Loading Default Payload *************************** */
    public static void Loading_Default_Payload(){
        CITab.CPtextArea1.setText(
            "ping%203|ping%20-c%202%20\n" +
            "ping%203|ping%20-n%202%20\n" +
            "dedsadsadsd|ping%20-c%202%20\n" +
            "dedsadsadsd|ping%20-n%202%20\n"
        );
    }


    /* *************************** Test Dns Server *************************** */
    public static void Test_Dns_Server(){

        boolean Use_Ceye = CITab.DScheckBox2.isSelected();
        String Ceye_Dns_Server = CITab.DStextField1.getText().trim();
        String Ceye_Token = CITab.DStextField2.getText().trim();
        String Dns_Server = CITab.DStextField3.getText().trim();
        String URL_With_Token = CITab.DStextField4.getText().trim();

        String DnsServer = "";
        String Content = Check_Dns_Fill();
        // 如果需要的数据没有填写
        if (Content.contains("Fail!")) {
            JOptionPane.showMessageDialog(null, Content , "Test Dns Server", JOptionPane.INFORMATION_MESSAGE);
        } else {
            // 选择 Use Ceye
            if (Use_Ceye) {
                DnsServer = Ceye_Dns_Server;
                String CeyeAPI = "http://api.ceye.io/v1/records?token=" + Ceye_Token + "&type=dns&filter=";
                // 获取添加随机值的 DnsSever
                String testsubdnsserver = Test_DnsServer(DnsServer);
                // 访问 API，检测是否 ping 成功以及获取访问的延迟时间
                String testContent = GET_Delay_And_TestDnsServer(CeyeAPI, testsubdnsserver);
                if (testContent.contains("Success")) {
                    String delay = testContent.replaceAll("Success!!!", "");
                    String point = "Success!\nDelay time is " + delay + "\nIf the delay exceeds 1200ms, please check DnsLog";
                    JOptionPane.showMessageDialog(null, point , "Test Dns Server", JOptionPane.INFORMATION_MESSAGE);
                } else if (testContent.contains("Fail")) {
                    String delay = testContent.replaceAll("Fail!!!", "");
                    String point = "Fail!\nNo DnsLog was found. Please check the Dns Server or Token, or change to another Dns Server"
                            + "\nDelay time is " + delay + "If it is a network problem, please try again";
                    JOptionPane.showMessageDialog(null, point , "Test Dns Server", JOptionPane.INFORMATION_MESSAGE);
                }
            } else {
                DnsServer = Dns_Server;
                String testsubdnsserver = Test_DnsServer(DnsServer);
                String testContent = GET_Delay_And_TestDnsServer(URL_With_Token, testsubdnsserver);
                if (testContent.contains("Success")) {
                    String delay = testContent.replaceAll("Success!!!", "");
                    String point = "Success!\nDelay time is " + delay + "\nIf the delay exceeds 1200ms, please check DnsLog";
                    JOptionPane.showMessageDialog(null, point , "Test Dns Server", JOptionPane.INFORMATION_MESSAGE);
                } else if (testContent.contains("Fail")) {
                    String delay = testContent.replaceAll("Fail!!!", "");
                    String point = "Fail!\nNo DnsLog was found. Please check the Dns Server or Token, or change to another Dns Server"
                            + "\nDelay time is " + delay + "If it is a network problem, please try again";
                    JOptionPane.showMessageDialog(null, point , "Test Dns Server", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        }
    }

    // 利用三组随机字符串拼接 Dns Server，并访问
    public static String Test_DnsServer(String dnsserver) {
        String random_str1 = RandomStringUtils.randomAlphanumeric(3);
        String random_str2 = RandomStringUtils.randomAlphanumeric(3);
        String random_str3 = RandomStringUtils.randomAlphanumeric(3);
        String testsubdnsserver = "I.m.testing." + random_str1 + "." + random_str2 + "." + random_str3 + "." + dnsserver;
        String indexUrl = "http://" + testsubdnsserver;
        OkHttpClient client = new OkHttpClient();
        Request loginReq = new Request.Builder()
                .url(indexUrl)
                .get()
                .build();
        Call call = client.newCall(loginReq);
        Response response = null;
        try {
            response = call.execute();
        } catch (IOException e) {
            e.printStackTrace(stderr);
        }
        return testsubdnsserver;
    }

    // 获取访问 API 请求延迟并检测是否 ping 成功
    public static String GET_Delay_And_TestDnsServer(String url, String testsubdnsserver) {
        long start = System.currentTimeMillis();
        OkHttpClient client = new OkHttpClient();
        String testresults = "";

        Request request = new Request.Builder()
                .url(url)
                .get()
                .build();

        try (Response response = client.newCall(request).execute()) {
            String responseBody = Objects.requireNonNull(response.body()).string();
            if (responseBody.toLowerCase().contains(testsubdnsserver.toLowerCase())) {
                testresults = "Success!!!";
            } else {
                testresults = "Fail!!!";
            }
        } catch (IOException e) {
            e.printStackTrace(stderr);
        }

        long end = System.currentTimeMillis();
        String testContent = testresults + (end - start) + "ms";
        return testContent;
    }

    // 检测所需值是否填写
    public static String Check_Dns_Fill() {
        boolean Use_Ceye = CITab.DScheckBox2.isSelected();
        String Ceye_Dns_Server = CITab.DStextField1.getText().trim();
        String Ceye_Token = CITab.DStextField2.getText().trim();
        boolean Use_Other_Dnslog = CITab.DScheckBox3.isSelected();
        String Dns_Server = CITab.DStextField3.getText().trim();
        String URL_With_Token = CITab.DStextField4.getText().trim();

        if (!Use_Ceye && !Use_Other_Dnslog) {
            return "Fail!\nYou need to choose to use <Use Ceye> or <Use Other Dnslog>";
        } else if (Use_Ceye && Ceye_Dns_Server.isEmpty() && Ceye_Token.isEmpty()) {
            return "Fail!\nYou need to fill in <Ceye Dns Server> and <Ceye Token>";
        } else if (Use_Ceye && Ceye_Dns_Server.isEmpty()) {
            return "Fail!\nYou need to fill in <Ceye Dns Server>";
        } else if (Use_Ceye && Ceye_Token.isEmpty()) {
            return "Fail!\nYou need to fill in <Ceye Token>";
        } else if (Use_Ceye) {
            return "Success!";
        } else if (Use_Other_Dnslog && Dns_Server.isEmpty() && URL_With_Token.isEmpty()) {
            return "Fail!\nYou need to fill to use <Dns Server> and <URL With Token>";
        } else if (Use_Other_Dnslog && Dns_Server.isEmpty()) {
            return "Fail!\nYou need to fill to use <Dns Server>";
        } else if (Use_Other_Dnslog && URL_With_Token.isEmpty()) {
            return "Fail!\nYou need to fill to use <URL With Token>";
        } else {
            return "Success!";
        }
    }
}

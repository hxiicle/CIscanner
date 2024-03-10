package burp.Application;
import burp.IBurpExtenderCallbacks;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;

public class GetDnsLog implements Callable<String> {

    private ExecutorService pool;
    private Boolean isStart;

    private String tokenUrl;
    private int ciTagId;

    private List<String> subDnsServerList;

    private PrintWriter stderr;


    public GetDnsLog(IBurpExtenderCallbacks callbacks, ExecutorService pool, Boolean isStart, String tokenUrl, int ciTagId, List<String> subDnsServerList) {
        this.pool = pool;
        this.isStart = isStart;
        this.tokenUrl = tokenUrl;
        this.ciTagId = ciTagId;
        this.subDnsServerList = subDnsServerList;

        this.stderr = new PrintWriter(callbacks.getStderr(), true);
    }

    @Override
    public String call() {
        try {
            while (isStart) {
                //this.stderr.println(this.tokenUrl);
                int isFindInt = 0;
                String httpResponseBody = null;
                httpResponseBody = sendGetRequest(this.tokenUrl);
                saveResponseBodyToFile("ciTagId: " + ciTagId + "\n");
                saveResponseBodyToFile(ciTagId + " [call - httpResponseBody] : " + httpResponseBody + "\n");
                for (String subDnsServer : this.subDnsServerList) {
                    //saveResponseBodyToFile(ciTagId +"[subDnsServer] : " + subDnsServer + "\n");
                    if (httpResponseBody.toLowerCase().contains(subDnsServer.toLowerCase())) {
                        //saveResponseBodyToFile(ciTagId + "[Find] : " + httpResponseBody + "\n"); // 追加保存responseBody至文件
                        isFindInt = isFindInt + 1;
                    }
                }
                if (isFindInt > 0) {
                    //this.stderr.println(ciTagId + "：" + ciTagId);
                    return "Find" + ciTagId;
                } else {
                    //this.stderr.println(ciTagId + "：" + ciTagId);
                    return "No" + ciTagId;
                }
            }
            pool.shutdownNow();
        } catch (Exception e) {
            this.stderr.println(e);
        }
        return null;
    }

    public String sendGetRequest(String urlString) {

        // 取消主机名验证
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        // 取消证书验证
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        SSLContext sc = null;
        try {
            sc = SSLContext.getInstance("TLS");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        try {
            Random random = new Random();

            int min = 2000;
            int max = 4000;

            int randomInt = random.nextInt(max - min + 1) + min;
            Thread.sleep(randomInt);
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                String response = getResponseBody(connection);
                return response;
            } else {
                //throw new IOException("HTTP request failed with response code: " + responseCode);
                Thread.sleep(randomInt);
                String response = getResponseBody(connection);
                return response;
            }
        } catch (Exception e) {
            this.stderr.println(e);
        }
        this.stderr.println("11111111111111111111111111");
        return null;
    }

    public String getResponseBody(HttpURLConnection connection) throws IOException  {

        // 取消主机名验证
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        // 取消证书验证
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        SSLContext sc = null;
        try {
            sc = SSLContext.getInstance("TLS");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try {
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        return response.toString();
    }

    private void saveResponseBodyToFile(String responseBody) {
        try {
            FileOutputStream fileOutputStream = new FileOutputStream("response.txt", true); // 追加写入文件
            OutputStreamWriter writer = new OutputStreamWriter(fileOutputStream);
            writer.write(responseBody);
            writer.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}

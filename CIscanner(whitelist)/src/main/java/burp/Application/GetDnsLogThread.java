package burp.Application;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.io.PrintWriter;

import burp.Application.GetDnsLog;
import burp.Bootstrap.CustomBurpUrl;
import burp.IBurpExtenderCallbacks;

public class GetDnsLogThread {
    private CustomBurpUrl customBurpUrl;

    private Map<Integer, List<String>> map;

    private GetDnsLog getDnsLog;

    private Boolean isStart;

    private String tokenUrl;

    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;

    private int threadInt;

    public GetDnsLogThread() {
    }

    public List<String> GetDnsLogThreadString(IBurpExtenderCallbacks callbacks, Map<Integer, List<String>> map, Boolean isStart, String tokenUrl, int threadInt) throws ExecutionException, InterruptedException {
        this.map = map;
        this.isStart = isStart;
        this.tokenUrl = tokenUrl;
        this.callbacks = callbacks;
        this.threadInt = threadInt;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        // 创建线程池
        ExecutorService pool = Executors.newFixedThreadPool(threadInt);

        List<Future<String>> futureList = new ArrayList<>();

        for (Map.Entry<Integer, List<String>> entry : map.entrySet()) {
            Integer key = entry.getKey();
            List<String> subDnsServerList = entry.getValue();
            Callable<String> callable = new GetDnsLog(callbacks, pool, isStart, tokenUrl, key, subDnsServerList);
            Future<String> task = pool.submit(callable);
            futureList.add(task);
        }

        String result;
        List<String> resultList = new ArrayList<>();
        for (Future<String> future : futureList) {
            result = future.get();

            resultList.add(result);
        }

        // 关闭线程池
        pool.shutdown();

        resultList.removeIf(String::isEmpty);
        return resultList;

    }
}


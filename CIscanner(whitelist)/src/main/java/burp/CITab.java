package burp;

import java.awt.*;
import java.io.*;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.swing.JOptionPane;

import org.apache.commons.lang3.RandomStringUtils;

import burp.Bootstrap.JTextAreaHintListener;

public class CITab extends AbstractTableModel implements ITab, IMessageEditorController {
    private final JPanel tabs;
    private JSplitPane mjSplitPane;
    private List<CITab.TablesData> Udatas = new ArrayList<CITab.TablesData>();
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;
    private CITab.URLTable Utable;
    private JScrollPane UscrollPane;
    private JSplitPane HjSplitPane;
    private JTabbedPane Ltable;
    private JTabbedPane Rtable;

    private String tagName;
    
    private JTextField threadNum;

    // 被动扫描开启复选框
    private JCheckBox isStartBox;
    // Use Ceye 的复选框
    private JCheckBox useCeyeBox;

    // Ceye Dns Server 的文本输入框
    private JTextField ceyeField1;

    // Ceye Token 的文本输入框
    private JTextField ceyeField2;

    // Use Other Dnslog 的复选框
    private JCheckBox useOtherBox;

    // Dns Server 的文本输入框
    private JTextField otherField1;

    // URL With Token 的文本输入框
    private JTextField otherField2;

    // Payload 的文本输入框
    private JTextArea payloadArea;

    // Whitelist 的文本输入框
    private JTextArea whiteListArea;

    private PrintWriter stdout;

    private PrintWriter stderr;

    private IBurpExtenderCallbacks callbacks;

    public CITab() {
        tabs = new JPanel(new BorderLayout());
    }

    public CITab(IBurpExtenderCallbacks callbacks, String name) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        this.tagName = name;

        tabs = new JPanel(new BorderLayout());

        // 主分隔面板
        mjSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mjSplitPane.setResizeWeight(0.5);

        // 任务栏面板
        Utable = new CITab.URLTable(CITab.this);
        UscrollPane = new JScrollPane(Utable);

        // 请求与响应界面的分隔面板规则
        HjSplitPane = new JSplitPane();
        HjSplitPane.setResizeWeight(0.5);

        // 请求的面板
        Ltable = new JTabbedPane();
        HRequestTextEditor = callbacks.createMessageEditor(CITab.this, false);
        Ltable.addTab("Request", HRequestTextEditor.getComponent());

        // 响应的面板
        Rtable = new JTabbedPane();
        HResponseTextEditor = callbacks.createMessageEditor(CITab.this, false);
        Rtable.addTab("Response", HResponseTextEditor.getComponent());

        /* *************************** Config *************************** */

        ////////////////////// passiveScanPanel //////////////////////
        JPanel passiveScanPanel = createTitledPanel("Passive Scan");
        isStartBox = new JCheckBox("Start");
        isStartBox.setForeground(new Color(255, 89, 18));
        // 复选框 Passive Scanning
        isStartBox.addActionListener(e -> {
            String Content = this.checkAllFill();
            if (Content.contains("Fail!")) {
                JOptionPane.showMessageDialog(null, Content, "Passive Scan", JOptionPane.INFORMATION_MESSAGE);
                isStartBox.setSelected(false);
            } else {
                isStartBox.setSelected(isStartBox.isSelected());
            }
        });
        passiveScanPanel.add(isStartBox);

        // 创建文本
        JLabel threadLabel = new JLabel("Thread :");
        // 创建文本输入框
        threadNum = new JTextField(2);
        threadNum.setToolTipText("1-10");
        passiveScanPanel.add(threadLabel);
        passiveScanPanel.add(threadNum);


        ////////////////////// ceyePanel //////////////////////
        // Ceye Config
        JPanel ceyePanel = createTitledPanel("Ceye Config");
        // 创建文本
        JLabel ceyeLabel1 = new JLabel("Use Ceye :");
        // 创建复选框
        useCeyeBox = new JCheckBox();
        // 创建文本
        JLabel ceyeLabel2 = new JLabel("Ceye Dns Server :");
        // 创建文本输入框
        ceyeField1 = new JTextField();
        // 创建文本
        JLabel ceyeLabel3 = new JLabel("Ceye Token :");
        // 创建文本输入框
        ceyeField2 = new JTextField();

        // Ceye Config-布局
        GroupLayout ceyeLayout = new GroupLayout(ceyePanel);
        ceyePanel.setLayout(ceyeLayout);
        // Ceye Config-设置组件之间的间隔
        ceyeLayout.setAutoCreateGaps(true);
        ceyeLayout.setAutoCreateContainerGaps(true);
        // Ceye Config-水平方向
        GroupLayout.SequentialGroup ceyehGroup = ceyeLayout.createSequentialGroup();
        // GroupLayout.Alignment.TRAILING：尾部对齐方式。尾部对齐是指组件的结束位置对齐
        ceyehGroup.addGroup(ceyeLayout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                .addComponent(ceyeLabel1)
                .addComponent(ceyeLabel2)
                .addComponent(ceyeLabel3));
        // GroupLayout.Alignment.LEADING：前部对齐方式。前部对齐是指组件的起始位置对齐
        ceyehGroup.addGroup(ceyeLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addComponent(useCeyeBox)
                .addComponent(ceyeField1)
                .addComponent(ceyeField2));
        ceyeLayout.setHorizontalGroup(ceyehGroup);
        // Ceye Config-垂直方向
        GroupLayout.SequentialGroup ceyevGroup = ceyeLayout.createSequentialGroup();
        ceyevGroup.addGroup(ceyeLayout.createParallelGroup()
                .addComponent(ceyeLabel1)
                .addComponent(useCeyeBox));
        // GroupLayout.Alignment.BASELINE：基线对齐方式。基线是指组件的文本行的基准线
        ceyevGroup.addGroup(ceyeLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(ceyeLabel2)
                .addComponent(ceyeField1));
        ceyevGroup.addGroup(ceyeLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(ceyeLabel3)
                .addComponent(ceyeField2));
        ceyeLayout.setVerticalGroup(ceyevGroup);

        ////////////////////// otherPanel //////////////////////
        // Other Dnslog Config
        JPanel otherPanel = createTitledPanel("Other Dnslog Config");
        // 创建文本
        JLabel otherLabel1 = new JLabel("Use Other Dnslog :");
        // 创建复选框
        useOtherBox = new JCheckBox();
        // 创建文本
        JLabel otherLabel2 = new JLabel("Dns Server :");
        // 创建文本输入框
        otherField1 = new JTextField();
        // 创建文本
        JLabel otherLabel3 = new JLabel("URL With Token :");
        // 创建文本输入框
        otherField2 = new JTextField();

        // Other Dnslog Config-布局
        GroupLayout otherLayout = new GroupLayout(otherPanel);
        otherPanel.setLayout(otherLayout);
        // Other Dnslog Config-设置组件之间的间隔
        otherLayout.setAutoCreateGaps(true);
        otherLayout.setAutoCreateContainerGaps(true);
        // Other Dnslog Config-水平方向
        GroupLayout.SequentialGroup otherhGroup = otherLayout.createSequentialGroup();
        // GroupLayout.Alignment.TRAILING：尾部对齐方式。尾部对齐是指组件的结束位置对齐
        otherhGroup.addGroup(otherLayout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                .addComponent(otherLabel1)
                .addComponent(otherLabel2)
                .addComponent(otherLabel3));
        // GroupLayout.Alignment.LEADING：前部对齐方式。前部对齐是指组件的起始位置对齐
        otherhGroup.addGroup(otherLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addComponent(useOtherBox)
                .addComponent(otherField1)
                .addComponent(otherField2));
        otherLayout.setHorizontalGroup(otherhGroup);
        // Other Dnslog Config-垂直方向
        GroupLayout.SequentialGroup othervGroup = otherLayout.createSequentialGroup();
        othervGroup.addGroup(otherLayout.createParallelGroup()
                .addComponent(otherLabel1)
                .addComponent(useOtherBox));
        // GroupLayout.Alignment.BASELINE：基线对齐方式。基线是指组件的文本行的基准线
        othervGroup.addGroup(otherLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(otherLabel2)
                .addComponent(otherField1));
        othervGroup.addGroup(otherLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(otherLabel3)
                .addComponent(otherField2));
        otherLayout.setVerticalGroup(othervGroup);

        ////////////////////// customPayloadsPanel //////////////////////
        // Custom Payloads
        JPanel customPayloadsPanel = createTitledPanel("Custom Payloads");
        // 创建文本
        JLabel payloadLabel = new JLabel("Payload :");
        // 创建文本输入框
        payloadArea = new JTextArea(5, 5);
        payloadArea.setToolTipText(
                "1. Payload格式: aaa{DNSSERVER}\n" +
                "2. 如果没有{DNSSERVER}，则默认直接追加至Payload后\n" +
                "3. 多个Payload中间加回车！"
        );
        payloadArea.setLineWrap(true);
        // 添加滚动条
        JScrollPane payloadScrollPane = new JScrollPane(payloadArea);
        // 创建文本
        JLabel whitelistLabel = new JLabel("Whitelist :");
        // 创建文本输入框
        whiteListArea = new JTextArea(5, 5);
        whiteListArea.setLineWrap(true);
        // 添加滚动条
        JScrollPane whiteListScrollPane = new JScrollPane(whiteListArea);

        // Custom Payloads-布局
        GroupLayout customLayout = new GroupLayout(customPayloadsPanel);
        customPayloadsPanel.setLayout(customLayout);
        // Custom Payloads-Custom Payloads面板-组件之间的间隔
        customLayout.setAutoCreateGaps(true);
        customLayout.setAutoCreateContainerGaps(true);
        // Custom Payloads-Custom Payloads面板-水平方向
        GroupLayout.SequentialGroup customhGroup = customLayout.createSequentialGroup();
        customhGroup.addGroup(customLayout.createParallelGroup(GroupLayout.Alignment.TRAILING)
                .addComponent(payloadLabel)
                .addComponent(whitelistLabel));
        customhGroup.addGroup(customLayout.createParallelGroup()
                .addComponent(payloadScrollPane)
                .addComponent(whiteListScrollPane));
        customLayout.setHorizontalGroup(customhGroup);
        // Custom Payloads-Custom Payloads面板-垂直方向
        GroupLayout.SequentialGroup customvGroup = customLayout.createSequentialGroup();
        customvGroup.addGroup(customLayout.createParallelGroup()
                .addComponent(payloadLabel)
                .addComponent(payloadScrollPane));
        customvGroup.addGroup(customLayout.createParallelGroup()
                .addComponent(whitelistLabel)
                .addComponent(whiteListScrollPane));
        customLayout.setVerticalGroup(customvGroup);
        // 复选框 Use Ceye 和 Use Other Dnslog 只能选一个
        useCeyeBox.addItemListener(e -> {
            if (useCeyeBox.isSelected()) {
                useOtherBox.setSelected(false);
            }
        });
        useOtherBox.addItemListener(e -> {
            if (useOtherBox.isSelected()) {
                useCeyeBox.setSelected(false);
            }
        });
        JButton button1 = new JButton("Save Configuration");
        // 鼠标在按钮上单击时触发的事件
        button1.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                saveConfiguration();
            }
        });
        JButton button2 = new JButton("Loading Default Payload");
        button2.setToolTipText("Will load the payload and the thread");
        button2.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                loadingDefaultPayload();
            }
        });
        JButton button3 = new JButton("Test Dns Server");
        button3.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                testDnsServer();
            }
        });

        ////////////////////// buttonPanel //////////////////////
        // 创建按钮面板
        JPanel buttonPanel = new JPanel();
        // 按钮面板-布局
        GroupLayout buttonlayout = new GroupLayout(buttonPanel);
        buttonPanel.setLayout(buttonlayout);
        // 组件之间的间隔
        buttonlayout.setAutoCreateGaps(true);
        buttonlayout.setAutoCreateContainerGaps(true);
        // 水平方向
        GroupLayout.SequentialGroup buttonhGroup = buttonlayout.createSequentialGroup();
        buttonhGroup.addGroup(buttonlayout.createParallelGroup()
                .addComponent(button1));
        buttonhGroup.addGroup(buttonlayout.createParallelGroup()
                .addComponent(button2));
        buttonhGroup.addGroup(buttonlayout.createParallelGroup()
                .addComponent(button3));
        buttonlayout.setHorizontalGroup(buttonhGroup);
        // 垂直方向
        GroupLayout.SequentialGroup buttonvGroup = buttonlayout.createSequentialGroup();
        buttonvGroup.addGroup(buttonlayout.createParallelGroup()
                .addComponent(button1)
                .addComponent(button2)
                .addComponent(button3));
        buttonlayout.setVerticalGroup(buttonvGroup);

        ////////////////////// config //////////////////////
        // 下方右边创建面板-config
        JPanel configPanel = new JPanel();
        Rtable.addTab("Config", configPanel);
        // Config-设置组件的布局
        GroupLayout Configlayout = new GroupLayout(configPanel);
        configPanel.setLayout(Configlayout);
        // Dns Server-设置组件之间的间隔
        Configlayout.setAutoCreateGaps(true);
        Configlayout.setAutoCreateContainerGaps(true);
        // Dns Server-水平方向
        GroupLayout.SequentialGroup DShGroup = Configlayout.createSequentialGroup();
        // GroupLayout.Alignment.CENTER：将组件在容器中水平和垂直方向上居中对齐
        DShGroup.addGroup(Configlayout.createParallelGroup(GroupLayout.Alignment.CENTER)
                .addComponent(passiveScanPanel)
                .addComponent(ceyePanel)
                .addComponent(otherPanel)
                .addComponent(customPayloadsPanel)
                .addComponent(buttonPanel));
        Configlayout.setHorizontalGroup(DShGroup);
        // Dns Server-垂直方向
        GroupLayout.SequentialGroup DSvGroup = Configlayout.createSequentialGroup();
        DSvGroup.addGroup(Configlayout.createParallelGroup()
                .addComponent(passiveScanPanel));
        DSvGroup.addGroup(Configlayout.createParallelGroup()
                .addComponent(ceyePanel));
        DSvGroup.addGroup(Configlayout.createParallelGroup()
                .addComponent(otherPanel));
        DSvGroup.addGroup(Configlayout.createParallelGroup()
                .addComponent(customPayloadsPanel));
        // 在面板DSpanel3和按钮面板BTpanel之间添加一个可变大小的间隔，使得按钮面板BTpanel紧贴底部
        //DSvGroup.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE);
        DSvGroup.addGroup(Configlayout.createParallelGroup()
                .addComponent(buttonPanel));
        Configlayout.setVerticalGroup(DSvGroup);

        // 自定义程序UI组件
        HjSplitPane.add(Ltable, "left");
        HjSplitPane.add(Rtable, "right");

        mjSplitPane.add(UscrollPane, "left");
        mjSplitPane.add(HjSplitPane, "right");

        tabs.add(mjSplitPane);

        // 自定义组件-导入
        callbacks.customizeUiComponent(tabs);
        // 将自定义选项卡添加到Burp的UI
        callbacks.addSuiteTab(CITab.this);

        // 如果存在配置文件，则加载配置文件的配置
        if (getConfigFile().exists()) {
            getConfigFileContent();
        } else {
            loadingDefaultPayload();
        }

        // 白名单提示
        whiteListArea.addFocusListener(new JTextAreaHintListener(whiteListArea,
                "1. 过滤某个域名: www.domain1.com\n" +
                "2. 过滤某个域名的全部子域名: *.domain2.com\n" +
                "3. 过滤某个域名的部分子域名: a.*.domain2.com 或者 *.a.*.domain2.com\n" +
                "4. 多个域名中间加回车！"));

        // 白名单提示
        payloadArea.addFocusListener(new JTextAreaHintListener(payloadArea,
        "1. Payload格式: aaa{DNSSERVER}\n" +
                "2. 如果没有{DNSSERVER}，则默认直接追加至Payload后\n" +
                "3. 多个Payload中间加回车！"));
    }

    private void getConfigFileContent() {

        String fileStart = fileGetValue(getConfigFile(),"IsStart").trim();
        String fileThread = fileGetValue(getConfigFile(),"ThreadNum").trim();
        String fileCeye = fileGetValue(getConfigFile(),"Ceye").trim();
        String fileCeyeDnsServer = fileGetValue(getConfigFile(),"Ceye Dns Server").trim();
        String fileCeyeToken = fileGetValue(getConfigFile(),"Ceye Token").trim();
        String fileOther = fileGetValue(getConfigFile(),"Other Dnslog").trim();
        String fileOtherDnsServer = fileGetValue(getConfigFile(),"Dns Server").trim();
        String fileOtherToken = fileGetValue(getConfigFile(),"URL With Token").trim();
        String filePayload = fileGetValue(getConfigFile(),"Payload").replace("; ", "\n").trim();
        String fileWhiteList = fileGetValue(getConfigFile(),"Whitelist").replace("; ", "\n").trim();

        this.threadNum.setText(fileThread);

        // Use Ceye 的复选框
        if (fileCeye.contains("1")) {
            this.useCeyeBox.setSelected(true);
        } else {
            this.useCeyeBox.setSelected(false);
        }
        // Ceye Dns Server 的文本输入框
        this.ceyeField1.setText(fileCeyeDnsServer);
        // Ceye Token 的文本输入框
        this.ceyeField2.setText(fileCeyeToken);

        // Use Other Dnslog 的复选框
        if (fileOther.contains("1")) {
            this.useOtherBox.setSelected(true);
        } else {
            this.useOtherBox.setSelected(false);
        }
        // Dns Server 的文本输入框
        this.otherField1.setText(fileOtherDnsServer);
        // URL With Token 的文本输入框
        this.otherField2.setText(fileOtherToken);

        // Payload 的文本输入框
        setPayloadArea(filePayload);
        // Whitelist 的文本输入框
        this.whiteListArea.setText(fileWhiteList);

        String Content = this.checkDnsFill();
        //this.stdout.println(Content);
        if (fileStart.contains("1") && !Content.contains("Fail!")) {
            this.isStartBox.setSelected(true);
        } else {
            this.isStartBox.setSelected(false);
        }
    }

    // 简化创建带标题的边框
    public JPanel createTitledPanel(String title) {
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder(title));
        return panel;
    }

    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    @Override
    public Component getUiComponent() {
        return this.tabs;
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public int getRowCount() {
        return this.Udatas.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "Method";
            case 2:
                return "URL";
            case 3:
                return "Status";
            case 4:
                return "Issue";
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        CITab.TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return datas.Id;
            case 1:
                return datas.Method;
            case 2:
                return datas.URL;
            case 3:
                return datas.Status;
            case 4:
                return datas.Issue;
        }
        return null;
    }

    /**
     * 新增任务至任务栏面板
     *
     * @param method
     * @param url
     * @param status
     * @param issue
     * @param requestResponse
     */
    public int add(String method, String url, String status, String issue,
                   IHttpRequestResponse requestResponse) {
        synchronized (this.Udatas) {
            int id = this.Udatas.size();
            this.Udatas.add(
                    new TablesData(
                            id,
                            method,
                            url,
                            status,
                            issue,
                            requestResponse
                    )
            );
            fireTableRowsInserted(id, id);
            return id;
        }
    }

    /**
     * 更新任务状态至任务栏面板
     *
     * @param id
     * @param method
     * @param url
     * @param status
     * @param issue
     * @param requestResponse
     */
    public int save(int id, String method, String url, String status, String issue,
                     IHttpRequestResponse requestResponse) {
        synchronized (this.Udatas) {
            this.Udatas.set(
                    id,
                    new TablesData(
                            id,
                            method,
                            url,
                            status,
                            issue,
                            requestResponse
                    )
            );
            fireTableRowsUpdated(id, id);
            return id;
        }
    }

    /**
     * 自定义Table
     */
    private class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            CITab.TablesData dataEntry = CITab.this.Udatas.get(convertRowIndexToModel(row));
            HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    /**
     * 界面显示数据存储模块
     */
    private static class TablesData {
        final int Id;
        final String Method;
        final String URL;
        final String Status;
        private String Issue;
        final IHttpRequestResponse requestResponse;

        public TablesData(int id, String method, String url,
                          String status, String issue,
                          IHttpRequestResponse requestResponse) {
            this.Id = id;
            this.Method = method;
            this.URL = url;
            this.Status = status;
            this.Issue = issue;
            this.requestResponse = requestResponse;
        }

        public void setIssue(String issue) {
            this.Issue = issue;
        }

        public int getId() {
            return Id;
        }
        public String getUrl() {
            return URL;
        }
    }

    /**
     * 更新任务状态至任务栏面板
     *
     * @param id
     */
    public void update(int id, String issue) {
        synchronized (Udatas) {
            for (int i = 0; i < Udatas.size(); i++) {
                TablesData data = Udatas.get(i);
                if (data.getId() == id) {
                    data.setIssue(issue);
                    fireTableRowsUpdated(id, 4);
                    if (issue.equals("Danger")) {
                        String url = data.getUrl();
                        PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);
                        stdout.println("\n================================================");
                        stdout.println("发现漏洞！");
                        stdout.println("URL是 " + url);
                        stdout.println("================================================");
                    }
                }
            }
        }
    }

    public Boolean isStart() {
        return this.isStartBox.isSelected();
    }

    public Boolean isUseCeye() {
        return this.useCeyeBox.isSelected();
    }

    public Boolean isUseOther() {
        return this.useOtherBox.isSelected();
    }

    public String getCeyeDnsServer() {
        return this.ceyeField1.getText().trim();
    }

    public String getCeyeToken() {
        return this.ceyeField2.getText().trim();
    }

    public String getOtherDnsServer() {
        return this.otherField1.getText().trim();
    }

    public String getOtherToken() {
        return this.otherField2.getText().trim();
    }

    public String getPayload() {
        return this.payloadArea.getText().trim();
    }

    public int getThread() {
        String threadString = this.threadNum.getText().trim();
        try {
            int threadInt = Integer.parseInt(threadString);
            if (threadInt < 1 || threadInt > 10) {
                return 4;
            } else {
                return threadInt;
            }
        }catch (Exception e) {
            return 4;
        }
    }

    public void setThreadNum(String threadNum) {
        this.threadNum.setText(threadNum);
    }

    public List<CITab.TablesData> getUdatas() {
        return this.Udatas;
    }

    public String getDnsServer() {
        if (this.isUseCeye()) {
            return this.getCeyeDnsServer();
        } else {
            return this.getOtherDnsServer();
        }
    }

    public String getToken() {
        if (this.isUseCeye()) {
            return "http://api.ceye.io/v1/records?token=" + this.getCeyeToken() + "&type=dns&filter=";
        } else {
            return this.getOtherToken();
        }
    }

    public String getWhiteList() {
        return this.whiteListArea.getText().trim();
    }

    public void setPayloadArea(String payloads) {
        this.payloadArea.setText(payloads);
    }

    public void setStartBoxFalse() {
        this.isStartBox.setSelected(false);
    }



    // 读取properties文件，根据key取出value
    public String fileGetValue(File f, String key){
        BufferedReader reader = null;
        String value = "";
        StringBuffer sbf = new StringBuffer();
        String output = "";
        try {
            reader = new BufferedReader(new FileReader(f));
            String tempStr;
            while ((tempStr = reader.readLine()) != null) {
                sbf.append(tempStr + '\n');
            }
            reader.close();
            output =  sbf.toString();
        } catch (IOException e) {}
        String[] properties_lists = output.split("\n");
        for (String str:properties_lists) {
            String[] str_lists = str.split(" = ",2);
            if (str_lists[0].equals(key))
                value = str_lists[1];
        }
        return value.trim();
    }

    public void saveConfiguration() {
        Boolean startBox = isStart();
        int threadInt = getThread();
        Boolean useCeye = isUseCeye();
        String ceyeDnsServer = getCeyeDnsServer();
        String ceyeToken = getCeyeToken();
        Boolean useOther = isUseOther();
        String otherDnsServer = getOtherDnsServer();
        String otherToken = getOtherToken();
        String payload = getPayload().replace("\n","; ");
        String whiteList = getWhiteList().replace("\n","; ");

        // 用于追加配置的字符串
        String total = "";

        // 是否开启被动扫描
        total = total +"[Passive]" + "\n";
        String startString;
        if (startBox) {
            startString = "1";
        } else {
            startString = "0";
        }
        total = total + "IsStart = " + startString + "\n";

        // 线程数
        total = total + "ThreadNum = " + threadInt + "\n";

        // 写入 Ceye 的值
        total = total +"[Ceye]" + "\n";
        String ceye;
        if (useCeye){
            ceye = "1";
        }else{
            ceye = "0";
        }
        total = total + "Ceye = " + ceye + "\n";

        // 写入 Ceye Dns Server
        total = total + "Ceye Dns Server = " + ceyeDnsServer + "\n";

        // 写入 Ceye Token
        total = total + "Ceye Token = " + ceyeToken + "\n";

        // Use Other Dnslog 的值
        total = total +"\n[Other Dnslog]" + "\n";
        String otherDnslog;
        if (useOther){
            otherDnslog = "1";
        }else{
            otherDnslog = "0";
        }
        total = total + "Other Dnslog = " + otherDnslog + "\n";

        // 写入 Dns Server
        total = total + "Dns Server = " + otherDnsServer + "\n";

        // 写入 URL With Token
        total = total + "URL With Token = " + otherToken + "\n";

        // 写入 Payload
        total = total + "\n[Payload]\nPayload = " + payload + "\n";

        // 写入 Whitelist
        total = total + "\n[Whitelist]\nWhitelist = " + whiteList;

        // 写入配置文件
        try (FileWriter fileWriter = new FileWriter(this.getConfigFile().getAbsolutePath())) {
            fileWriter.append(total);
        } catch (IOException e) {
            e.printStackTrace(this.stderr);
        }

        // 判断是否有未按照要求填入的值
        String Content = this.checkAllFill();

        JOptionPane.showMessageDialog(null, Content , "Save", JOptionPane.INFORMATION_MESSAGE);
    }

    // 获取配置文件路径
    public File getConfigFile() {
        String os = System.getProperty("os.name").toLowerCase();
        String configFile;

        if (os.startsWith("win")) {
            configFile = "CIScanner.properties";
        } else {
            String jarPath = this.callbacks.getExtensionFilename();
            String directory = (new File(jarPath)).getParent();
            configFile = directory + File.separator + "CIScanner.properties";
        }

        return new File(configFile);
    }

    public String checkAllFill() {
        Boolean useCeye = isUseCeye();
        String ceyeDnsServer = getCeyeDnsServer();
        String ceyeToken = getCeyeToken();
        Boolean useOther = isUseOther();
        String otherDnsServer = getOtherDnsServer();
        String otherToken = getOtherToken();
        String payload = getPayload().replace("\n","; ");
        // 提示信息
        String Content = "";
        if (!useCeye && !useOther) {
            Content = "Fail!\nYou need to choose to use <Use Ceye> or <Use Other Dnslog>";
        } else if (useCeye && ceyeDnsServer.isEmpty() && ceyeToken.isEmpty() && payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Dns Server> , <Ceye Token> and <Payload>";
        } else if (useCeye && ceyeDnsServer.isEmpty() && !ceyeToken.isEmpty() && payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Dns Server> and <Payload>";
        } else if (useCeye && ceyeDnsServer.isEmpty() && ceyeToken.isEmpty() && !payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Dns Server> and <Ceye Token>";
        } else if (useCeye && ceyeDnsServer.isEmpty() && !ceyeToken.isEmpty() && !payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Dns Server>";

        } else if (useCeye && !ceyeDnsServer.isEmpty() && ceyeToken.isEmpty() && payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Token> and <Payload>";
        } else if (useCeye && !ceyeDnsServer.isEmpty() && !ceyeToken.isEmpty() && payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Payload>";
        } else if (useCeye && !ceyeDnsServer.isEmpty() && ceyeToken.isEmpty() && !payload.isEmpty()) {
            Content = "Fail!\nYou need to fill in <Ceye Token>";
        } else if (useCeye && !ceyeDnsServer.isEmpty() && !ceyeToken.isEmpty() && !payload.isEmpty()) {
            Content = "Success!";

        } else if (useOther && otherDnsServer.isEmpty() && otherToken.isEmpty() && payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <Dns Server> , <URL With Token> and <Payload>";
        } else if (useOther && otherDnsServer.isEmpty() && !otherToken.isEmpty() && payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <Dns Server> and <Payload>";
        } else if (useOther && otherDnsServer.isEmpty() && otherToken.isEmpty() && !payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <Dns Server> and <URL With Token>";
        } else if (useOther && otherDnsServer.isEmpty() && !otherToken.isEmpty() && !payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <Dns Server>";

        } else if (useOther && !otherDnsServer.isEmpty() && otherToken.isEmpty() && payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <URL With Token> and <Payload>";
        } else if (useOther && !otherDnsServer.isEmpty() && !otherToken.isEmpty() && payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <Payload>";
        } else if (useOther && !otherDnsServer.isEmpty() && otherToken.isEmpty() && !payload.isEmpty()) {
            Content = "Fail!\nYou need to fill to use <URL With Token>";
        } else if (useOther && !otherDnsServer.isEmpty() && !otherToken.isEmpty() && !payload.isEmpty()) {
            Content = "Success!";
        }
        return Content;
    }

    // Loading Default Payload
    public void loadingDefaultPayload(){
        String defaultPayloads = "ping%203|ping%20-c%202%20\n" +
                "ping%203|ping%20-n%202%20\n" +
                "dedsadsadsd|ping%20-c%202%20\n" +
                "dedsadsadsd|ping%20-n%202%20\n";
        String threadNum = "4";
        this.setThreadNum(threadNum);
        this.setPayloadArea(defaultPayloads);
    }

    // Test Dns Server
    public void testDnsServer(){
        Boolean useCeye = isUseCeye();
        String ceyeDnsServer = getCeyeDnsServer();
        String ceyeToken = getCeyeToken();
        String otherDnsServer = getOtherDnsServer();
        String otherToken = getOtherToken();

        String dnsServer = "";
        String content = this.checkAllFill();
        // 如果需要的数据没有填写
        try {
            if (content.contains("Fail!")) {
                JOptionPane.showMessageDialog(null, content , "Test Dns Server", JOptionPane.INFORMATION_MESSAGE);
            } else {
                // 选择 Use Ceye
                if (useCeye) {
                    dnsServer = ceyeDnsServer;
                    String ceyeAPI = "http://api.ceye.io/v1/records?token=" + ceyeToken + "&type=dns&filter=";
                    // 获取添加随机值的 DnsSever
                    String testSubDnsServer = this.sendPing(dnsServer);
                    // 访问 API，检测是否 ping 成功以及获取访问的延迟时间
                    String testContent = this.sendGetRequestAndDelay(ceyeAPI, testSubDnsServer);
                    //this.stdout.println("testContent：" + testContent + "\n");
                    JOptionPane.showMessageDialog(null, testContent , "Test Dns Server", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    dnsServer = otherDnsServer;
                    String testSubDnsServer = this.sendPing(dnsServer);
                    String testContent = this.sendGetRequestAndDelay(otherToken, testSubDnsServer);
                    JOptionPane.showMessageDialog(null, testContent , "Test Dns Server", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        } catch(Exception e) {
            JOptionPane.showMessageDialog(null, e , "Test Dns Server", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    // 利用三组随机字符串拼接 Dns Server，并ping
    public String sendPing(String dnsServer) {
        String randomStr1 = RandomStringUtils.randomAlphanumeric(3);
        String randomStr2 = RandomStringUtils.randomAlphanumeric(3);
        String randomStr3 = RandomStringUtils.randomAlphanumeric(3);
        String testSubDnsServer = "I.m.testing." + randomStr1 + "." + randomStr2 + "." + randomStr3 + "." + dnsServer;
        try {
            InetAddress inetAddress = InetAddress.getByName(testSubDnsServer);
            inetAddress.isReachable(10);
        } catch (Exception e) {
            //this.stderr.println("ping:" + e);
            return testSubDnsServer;
        }
        return testSubDnsServer;
    }

    // 获取访问 API 请求延迟并检测是否 ping 成功
    public String sendGetRequestAndDelay(String urlString, String testSubDnsServer) {
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


        long startTime = System.currentTimeMillis();
        String testResults = "";

        try {
            URL url = new URL(urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000); // 设置连接超时时间为5秒
            connection.setReadTimeout(5000); // 设置读取超时时间为5秒

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();

                String responseBody = response.toString();
                boolean containsSubDnsServer = responseBody.toLowerCase().contains(testSubDnsServer.toLowerCase());
                //this.stdout.println("responseBody.toLowerCase:" + responseBody.toLowerCase());
                //this.stdout.println("testSubDnsServer.toLowerCase:" + testSubDnsServer.toLowerCase());


                long endTime = System.currentTimeMillis();
                long delay = endTime - startTime;

                if (containsSubDnsServer) {
                    testResults = "Success!\nDelay time is " + delay + "ms\nIf the delay exceeds 1200ms, please check DnsServer";
                } else {
                    testResults = "Fail!\nNo DnsLog was found. Please try again!\nOr you can check the Dns Server and Token, or change to another Dns Server"
                            + "\nDelay time is " + delay + "ms";
                }
            } else {
                throw new IOException("HTTP request failed with response code: " + responseCode);
            }
        } catch (SocketTimeoutException e) {
            // 处理读取超时异常
            testResults = "Fail!\nDelay time > 5s! Please check your Dns Server or try again!";
        } catch (IOException e) {
            testResults = e.toString();
        }
        return testResults;
    }

    // 检测所需值是否填写
    public String checkDnsFill() {
        Boolean useCeye = isUseCeye();
        String ceyeDnsServer = getCeyeDnsServer();
        String ceyeToken = getCeyeToken();
        Boolean useOther = isUseOther();
        String otherDnsServer = getOtherDnsServer();
        String otherToken = getOtherToken();
        String payloadString = getPayload();

        if (useCeye == Boolean.TRUE) {
            if (!ceyeDnsServer.isEmpty() && !ceyeToken.isEmpty() && !payloadString.isEmpty()) {
                return "Success!";
            }
        }
        if (useOther == Boolean.TRUE) {
            if (!otherDnsServer.isEmpty() && !otherToken.isEmpty() && !payloadString.isEmpty()) {
                return "Success!";
            }
        }
        return "Fail!";
    }

}
package burp;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class CITab extends AbstractTableModel implements ITab, IMessageEditorController {
    private static IMessageEditor MRequestTextEditor;
    private static IMessageEditor MResponseTextEditor;

    public static JCheckBox DScheckBox1;
    // Use Ceye 的复选框
    public static JCheckBox DScheckBox2;

    // Ceye Dns Server 的文本输入框
    public static JTextField DStextField1;

    // Ceye Token 的文本输入框
    public static JTextField DStextField2;

    // Use Other Dnslog 的复选框
    public static JCheckBox DScheckBox3;

    // Dns Server 的文本输入框
    public static JTextField DStextField3;

    // URL With Token 的文本输入框
    public static JTextField DStextField4;

    // Payload 的文本输入框
    public static JTextArea CPtextArea1;

    // Whitelist 的文本输入框
    public static JTextArea CPtextArea2;

    public static List<TablesData> Udatas = new ArrayList();
    public static URLTable Utable;
    public static IHttpRequestResponse currentlyDisplayedItem;

    // 获取选项卡内容组件
    @Override
    public Component getUiComponent() {
        /* *************************** URL列表 *************************** */
        // 上方面板创建表格
        Utable = new URLTable(this);
        // 上方面板设置可滚动，JScrollPane，提供了一个可滚动视图区域，当内容超过视图区域的大小时，它会自动显示滚动条
        JScrollPane scrollPane = new JScrollPane(Utable);

        /* *************************** 请求包 *************************** */
        // 下方左边的面板创建选项卡式的界面，允许用户在多个标签页之间切换
        JTabbedPane bottomlefttabbedPane = new JTabbedPane();

        // 修改后的请求包
        MRequestTextEditor = BurpExtender.callbacks.createMessageEditor(this, false);
        bottomlefttabbedPane.addTab("Request", MRequestTextEditor.getComponent());



        /* *************************** 响应包 *************************** */
        // 下方右边创建选项卡式的面板
        JTabbedPane bottomrighttabbedPane = new JTabbedPane();

        // 修改后的响应包
        MResponseTextEditor = BurpExtender.callbacks.createMessageEditor(this, false);
        bottomrighttabbedPane.addTab("Response", MResponseTextEditor.getComponent());


        /* *************************** Config *************************** */
        /*
        // 创建config面板下的标签页1-Dns Server
        JPanel right3panel1 = new JPanel();
        right3tabbedPane.addTab("Dns Server", right3panel1);
        */
        // Dns Server-创建带有标题的边框1
        JPanel DSpanel1 = createTitledPanel("Passive Scan");
        // 创建带有指定标签文本的复选框
        DScheckBox1 = new JCheckBox("Open       ");
        DScheckBox1.setForeground(new Color(255, 89, 18));
        // 复选框 Passive Scanning
        DScheckBox1.addActionListener(e -> {
            String Content = ButtonFunction.Check_All_Fill();
            if (Content.contains("Fail!")) {
                JOptionPane.showMessageDialog(null, Content, "Passive Scan", JOptionPane.INFORMATION_MESSAGE);
                DScheckBox1.setSelected(false);
            } else {
                DScheckBox1.setSelected(DScheckBox1.isSelected());
            }
        });
        DSpanel1.add(DScheckBox1);
        // 使用下面的语句会使边框变为复选框大小
        DSpanel1.setLayout(new BoxLayout(DSpanel1, BoxLayout.X_AXIS));

        // Dns Server-创建带有标题的边框2-Ceye Config
        JPanel DSpanel2 = createTitledPanel("Ceye Config");
        // 创建文本
        JLabel DSlabel1 = new JLabel("Use Ceye :");
        // 创建复选框
        DScheckBox2 = new JCheckBox();
        // 创建文本
        JLabel DSlabel2 = new JLabel("Ceye Dns Server :");
        // 创建文本输入框
        DStextField1 = new JTextField();
        // 创建文本
        JLabel DSlabel3 = new JLabel("Ceye Token :");
        // 创建文本输入框
        DStextField2 = new JTextField();

        // Ceye Config-设置组件的布局
        GroupLayout DSlayout1 = new GroupLayout(DSpanel2);
        DSpanel2.setLayout(DSlayout1);
        // Ceye Config-设置组件之间的间隔
        DSlayout1.setAutoCreateGaps(true);
        DSlayout1.setAutoCreateContainerGaps(true);
        // Ceye Config-水平方向
        GroupLayout.SequentialGroup DShGroup1 = DSlayout1.createSequentialGroup();
        // GroupLayout.Alignment.TRAILING：尾部对齐方式。尾部对齐是指组件的结束位置对齐
        DShGroup1.addGroup(DSlayout1.createParallelGroup(GroupLayout.Alignment.TRAILING)
                .addComponent(DSlabel1)
                .addComponent(DSlabel2)
                .addComponent(DSlabel3));
        // GroupLayout.Alignment.LEADING：前部对齐方式。前部对齐是指组件的起始位置对齐
        DShGroup1.addGroup(DSlayout1.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addComponent(DScheckBox2)
                .addComponent(DStextField1)
                .addComponent(DStextField2));
        DSlayout1.setHorizontalGroup(DShGroup1);
        // Ceye Config-垂直方向
        GroupLayout.SequentialGroup DSvGroup1 = DSlayout1.createSequentialGroup();
        DSvGroup1.addGroup(DSlayout1.createParallelGroup()
                .addComponent(DSlabel1)
                .addComponent(DScheckBox2));
        // GroupLayout.Alignment.BASELINE：基线对齐方式。基线是指组件的文本行的基准线
        DSvGroup1.addGroup(DSlayout1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(DSlabel2)
                .addComponent(DStextField1));
        DSvGroup1.addGroup(DSlayout1.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(DSlabel3)
                .addComponent(DStextField2));
        DSlayout1.setVerticalGroup(DSvGroup1);

        // Dns Server-创建带有标题的边框3-Other Dnslog Config
        JPanel DSpanel3 = createTitledPanel("Other Dnslog Config");
        // 创建文本
        JLabel DSlabel4 = new JLabel("Use Other Dnslog :");
        // 创建复选框
        DScheckBox3 = new JCheckBox();
        // 创建文本
        JLabel DSlabel5 = new JLabel("Dns Server :");
        // 创建文本输入框
        DStextField3 = new JTextField();
        // 创建文本
        JLabel DSlabel6 = new JLabel("URL With Token :");
        // 创建文本输入框
        DStextField4 = new JTextField();

        // Other Dnslog Config-设置组件的布局
        GroupLayout DSlayout2 = new GroupLayout(DSpanel3);
        DSpanel3.setLayout(DSlayout2);
        // Other Dnslog Config-设置组件之间的间隔
        DSlayout2.setAutoCreateGaps(true);
        DSlayout2.setAutoCreateContainerGaps(true);
        // Other Dnslog Config-水平方向
        GroupLayout.SequentialGroup DShGroup2 = DSlayout2.createSequentialGroup();
        // GroupLayout.Alignment.TRAILING：尾部对齐方式。尾部对齐是指组件的结束位置对齐
        DShGroup2.addGroup(DSlayout2.createParallelGroup(GroupLayout.Alignment.TRAILING)
                .addComponent(DSlabel4)
                .addComponent(DSlabel5)
                .addComponent(DSlabel6));
        // GroupLayout.Alignment.LEADING：前部对齐方式。前部对齐是指组件的起始位置对齐
        DShGroup2.addGroup(DSlayout2.createParallelGroup(GroupLayout.Alignment.LEADING)
                .addComponent(DScheckBox3)
                .addComponent(DStextField3)
                .addComponent(DStextField4));
        DSlayout2.setHorizontalGroup(DShGroup2);
        // Other Dnslog Config-垂直方向
        GroupLayout.SequentialGroup DSvGroup2 = DSlayout2.createSequentialGroup();
        DSvGroup2.addGroup(DSlayout2.createParallelGroup()
                .addComponent(DSlabel4)
                .addComponent(DScheckBox3));
        // GroupLayout.Alignment.BASELINE：基线对齐方式。基线是指组件的文本行的基准线
        DSvGroup2.addGroup(DSlayout2.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(DSlabel5)
                .addComponent(DStextField3));
        DSvGroup2.addGroup(DSlayout2.createParallelGroup(GroupLayout.Alignment.BASELINE)
                .addComponent(DSlabel6)
                .addComponent(DStextField4));
        DSlayout2.setVerticalGroup(DSvGroup2);

        // Custom Payloads-创建带有标题的边框1-Custom Payloads
        JPanel CPpanel1 = createTitledPanel("Custom Payloads");
        // 创建文本
        JLabel CPlabel1 = new JLabel("Payload :");
        // 创建文本输入框
        CPtextArea1 = new JTextArea(5, 5);
        CPtextArea1.setLineWrap(true);
        // 添加滚动条
        JScrollPane CPscrollPane1 = new JScrollPane(CPtextArea1);
        // 创建文本
        JLabel CPlabel2 = new JLabel("Whitelist :");
        // 创建文本输入框
        CPtextArea2 = new JTextArea(5, 5);
        CPtextArea2.setLineWrap(true);
        // 添加滚动条
        JScrollPane CPscrollPane2 = new JScrollPane(CPtextArea2);

        // Custom Payloads-Custom Payloads面板-布局
        GroupLayout CPlayout1 = new GroupLayout(CPpanel1);
        CPpanel1.setLayout(CPlayout1);
        // Custom Payloads-Custom Payloads面板-组件之间的间隔
        CPlayout1.setAutoCreateGaps(true);
        CPlayout1.setAutoCreateContainerGaps(true);
        // Custom Payloads-Custom Payloads面板-水平方向
        GroupLayout.SequentialGroup CPhGroup1 = CPlayout1.createSequentialGroup();
        CPhGroup1.addGroup(CPlayout1.createParallelGroup(GroupLayout.Alignment.TRAILING)
                .addComponent(CPlabel1)
                .addComponent(CPlabel2));
        CPhGroup1.addGroup(CPlayout1.createParallelGroup()
                .addComponent(CPscrollPane1)
                .addComponent(CPscrollPane2));
        CPlayout1.setHorizontalGroup(CPhGroup1);
        // Custom Payloads-Custom Payloads面板-垂直方向
        GroupLayout.SequentialGroup CPvGroup1 = CPlayout1.createSequentialGroup();
        CPvGroup1.addGroup(CPlayout1.createParallelGroup()
                .addComponent(CPlabel1)
                .addComponent(CPscrollPane1));
        CPvGroup1.addGroup(CPlayout1.createParallelGroup()
                .addComponent(CPlabel2)
                .addComponent(CPscrollPane2));
        CPlayout1.setVerticalGroup(CPvGroup1);


        // 复选框 Use Ceye 和 Use Other Dnslog 只能选一个
        DScheckBox2.addItemListener(e -> {
            if (DScheckBox2.isSelected()) {
                DScheckBox3.setSelected(false);
            }
        });
        DScheckBox3.addItemListener(e -> {
            if (DScheckBox3.isSelected()) {
                DScheckBox2.setSelected(false);
            }
        });
        // Dns Server-创建按钮
        JButton button1 = new JButton("Save Configuration");
        // 鼠标在按钮上单击时触发的事件
        button1.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                ButtonFunction.Save_Configuration();
            }
        });
        JButton button2 = new JButton("Loading Default Payload");
        // 鼠标在按钮上单击时触发的事件
        button2.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                ButtonFunction.Loading_Default_Payload();
            }
        });
        JButton button3 = new JButton("Test Dns Server");
        // 鼠标在按钮上单击时触发的事件
        button3.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                ButtonFunction.Test_Dns_Server();
            }
        });
        // Dns Server-创建按钮面板1
        JPanel BTpanel1 = new JPanel();
        // Dns Server-按钮面板1-布局
        GroupLayout BTlayout1 = new GroupLayout(BTpanel1);
        BTpanel1.setLayout(BTlayout1);
        // Dns Server-按钮面板1-组件之间的间隔
        BTlayout1.setAutoCreateGaps(true);
        BTlayout1.setAutoCreateContainerGaps(true);
        // Dns Server-按钮面板1-水平方向
        GroupLayout.SequentialGroup BThGroup1 = BTlayout1.createSequentialGroup();
        BThGroup1.addGroup(BTlayout1.createParallelGroup()
                .addComponent(button1));
        BThGroup1.addGroup(BTlayout1.createParallelGroup()
                .addComponent(button2));
        BThGroup1.addGroup(BTlayout1.createParallelGroup()
                .addComponent(button3));
        BTlayout1.setHorizontalGroup(BThGroup1);
        // Dns Server-按钮面1-垂直方向
        GroupLayout.SequentialGroup BTvGroup1 = BTlayout1.createSequentialGroup();
        BTvGroup1.addGroup(BTlayout1.createParallelGroup()
                .addComponent(button1)
                .addComponent(button2)
                .addComponent(button3));
        BTlayout1.setVerticalGroup(BTvGroup1);

        // 下方右边创建面板-config
        JPanel right3panel = new JPanel();
        bottomrighttabbedPane.addTab("Config", right3panel);
        // Config-设置组件的布局
        GroupLayout Configlayout = new GroupLayout(right3panel);
        right3panel.setLayout(Configlayout);
        // Dns Server-设置组件之间的间隔
        Configlayout.setAutoCreateGaps(true);
        Configlayout.setAutoCreateContainerGaps(true);
        // Dns Server-水平方向
        GroupLayout.SequentialGroup DShGroup = Configlayout.createSequentialGroup();
        // GroupLayout.Alignment.CENTER：将组件在容器中水平和垂直方向上居中对齐
        DShGroup.addGroup(Configlayout.createParallelGroup(GroupLayout.Alignment.CENTER)
                .addComponent(DSpanel1)
                .addComponent(DSpanel2)
                .addComponent(DSpanel3)
                .addComponent(CPpanel1)
                .addComponent(BTpanel1));
        Configlayout.setHorizontalGroup(DShGroup);
        // Dns Server-垂直方向
        GroupLayout.SequentialGroup DSvGroup = Configlayout.createSequentialGroup();
        DSvGroup.addGroup(Configlayout.createParallelGroup()
                .addComponent(DSpanel1));
        DSvGroup.addGroup(Configlayout.createParallelGroup()
                .addComponent(DSpanel2));
        DSvGroup.addGroup(Configlayout.createParallelGroup()
                .addComponent(DSpanel3));
        DSvGroup.addGroup(Configlayout.createParallelGroup()
                .addComponent(CPpanel1));
        // 在面板DSpanel3和按钮面板BTpanel之间添加一个可变大小的间隔，使得按钮面板BTpanel紧贴底部
        //DSvGroup.addPreferredGap(LayoutStyle.ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE);
        DSvGroup.addGroup(Configlayout.createParallelGroup()
                .addComponent(BTpanel1));
        Configlayout.setVerticalGroup(DSvGroup);

        /* *************************** 其他 *************************** */
        // 创建下方面板，左右分割成两个面板，且中间的分割线可移动
        JSplitPane bottomPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, bottomlefttabbedPane, bottomrighttabbedPane);
        bottomPane.setResizeWeight(0.5);

        // 上下分割成两个面板
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scrollPane, bottomPane);
        // 分割线的位置占JSplitPane的百分比
        splitPane.setResizeWeight(0.5);
        //根据Burp的UI样式自定义UI组件，包括字体大小、颜色、表格行距等
        BurpExtender.callbacks.customizeUiComponent(splitPane);

        // 如果存在配置文件，则加载配置文件的配置
        if (getConfigFile().exists()) {
            String Ceye = FileGetValue(getConfigFile(),"Ceye").trim();
            String Ceye_Dns_Serve = FileGetValue(getConfigFile(),"Ceye Dns Server").trim();
            String Ceye_Token = FileGetValue(getConfigFile(),"Ceye Token").trim();
            String Other_Dnslog = FileGetValue(getConfigFile(),"Other Dnslog").trim();
            String Dns_Server = FileGetValue(getConfigFile(),"Dns Server").trim();
            String URL_With_Token = FileGetValue(getConfigFile(),"URL With Token").trim();
            String Payload = FileGetValue(getConfigFile(),"Payload").replace("; ", "\n").trim();
            String Target_Host = FileGetValue(getConfigFile(),"Whitelist").replace("; ", "\n").trim();
            // Use Ceye 的复选框
            if (Ceye.contains("1")) {
                DScheckBox2.setSelected(true);
            } else {
                DScheckBox2.setSelected(false);
            }
            // Ceye Dns Server 的文本输入框
            DStextField1.setText(Ceye_Dns_Serve);
            // Ceye Token 的文本输入框
            DStextField2.setText(Ceye_Token);

            // Use Other Dnslog 的复选框
            if (Other_Dnslog.contains("1")) {
                DScheckBox3.setSelected(true);
            } else {
                DScheckBox3.setSelected(false);
            }
            // Dns Server 的文本输入框
            DStextField3.setText(Dns_Server);
            // URL With Token 的文本输入框
            DStextField4.setText(URL_With_Token);

            // Payload 的文本输入框
            CPtextArea1.setText(Payload);

            // Whitelist 的文本输入框
            CPtextArea2.setText(Target_Host);
        } else {
            CPtextArea1.setText(
                    "ping%203|ping%20-c%202%20\n" +
                            "ping%203|ping%20-n%202%20\n" +
                            "dedsadsadsd|ping%20-c%202%20\n" +
                            "dedsadsadsd|ping%20-n%202%20\n"
            );
        }
        return splitPane;
    }
    @Override
    public String getTabCaption() {
        return "CIscanner";
    }

    // 简化创建带标题的边框
    public static JPanel createTitledPanel(String title) {
        JPanel panel = new JPanel();
        panel.setBorder(BorderFactory.createTitledBorder(title));
        return panel;
    }

    // 获取配置文件路径
    public static File getConfigFile() {
        String os = System.getProperty("os.name").toLowerCase();
        String configFile;

        if (os.startsWith("win")) {
            configFile = "CIScanner.properties";
        } else {
            String jarPath = BurpExtender.callbacks.getExtensionFilename();
            String directory = (new File(jarPath)).getParent();
            configFile = directory + File.separator + "CIScanner.properties";
        }

        return new File(configFile);
    }

    // 读取properties文件，根据key取出value
    public String FileGetValue(File f, String key){
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


    public int getRowCount() {
        return Udatas.size();
    }

    public int getColumnCount() {
        return 5;
    }

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

    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = Udatas.get(rowIndex);
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
     * 自定义Table
     */
    private static class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            CITab.TablesData dataEntry = Udatas.get(convertRowIndexToModel(row));
            MRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            MResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    public static class TablesData {
        private int Id;

        private String Method;

        private String URL;

        private String Status;

        private String Issue;

        private IHttpRequestResponse requestResponse;

        public TablesData (int id, String method, String url,
                          String status, String issue,
                          IHttpRequestResponse requestResponse) {
            this.Id = id;
            this.Method = method;
            this.URL = url;
            this.Status = status;
            this.Issue = issue;
            this.requestResponse = requestResponse;
        }

        public int getId() {
            return Id;
        }

        public void setIssue(String issue) {
            this.Issue = issue;
        }

        public String getUrl() {
            return URL;
        }
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
    public void add(String method, String url, String status, String issue,
                   IHttpRequestResponse requestResponse) {
        synchronized (Udatas) {
            int id = Udatas.size();
            Udatas.add(
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
        }
    }

    /**
     * 更新任务状态至任务栏面板
     *
     * @param id
     */
    public void update(int id) {
        synchronized (Udatas) {
            for (int i = 0; i < Udatas.size(); i++) {
                TablesData data = Udatas.get(i);
                if (data.getId() == id) {
                    data.setIssue("Danger");
                    fireTableRowsUpdated(id, 4);
                    String url = data.getUrl();
                    PrintWriter stdout = new PrintWriter(BurpExtender.callbacks.getStdout(), true);
                    stdout.println("\n================================================");
                    stdout.println("发现漏洞！");
                    stdout.println("URL是 " + url);
                    stdout.println("================================================");
                }
            }
        }
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

}
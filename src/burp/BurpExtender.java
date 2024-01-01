package burp;

import java.io.PrintWriter;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    public static IExtensionHelpers helpers;
    public static IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        try{
            this.callbacks = callbacks;
            this.helpers = callbacks.getHelpers();
            // 设置插件名称
            callbacks.setExtensionName("CIscanner");
            //callbacks.registerContextMenuFactory(new CIMenu());
            callbacks.addSuiteTab(new CITab());
            callbacks.registerScannerCheck(new PassiveScan());
            callbacks.issueAlert("CIscanner installed.");
            callbacks.registerExtensionStateListener(this);
        }catch(Exception e){
            PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
            stderr.println(e);
        }

        String title = ""
                +"\n[-]Plugin Name:\tCIscanner"
                +"\n[-]Version:\t\t\t1.0"
                +"\n[-]Author:\t\t\thxiicle"
                +"\n[-]Statement:\t\tOnly allowed for cyber security research!Prohibited for illegal purposes!"
                +"\n\n*** Please activate the plug-in before use";
        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println(title);

    }

    public void extensionUnloaded() {
        CITab.DScheckBox1.setSelected(false);
    }
}
package burp;

import javax.swing.*;
import java.util.ArrayList;
import java.util.List;

public class CIMenu implements IContextMenuFactory {
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation){
        List<JMenuItem> Menus = new ArrayList<>();
        JMenu MainMenu = new JMenu("CIscanner");

        JMenuItem Send = new JMenuItem("Send to CIscanner");

        MainMenu.add(Send);

        Menus.add(MainMenu);
        return Menus;
    }


}
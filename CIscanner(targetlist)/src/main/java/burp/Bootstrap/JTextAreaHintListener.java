package burp.Bootstrap;

import java.awt.Color;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;

import javax.swing.*;

public class JTextAreaHintListener implements FocusListener {
    private String hintText;
    private JTextArea textArea;


    public JTextAreaHintListener(JTextArea textArea,String hintText) {
        this.textArea = textArea;
        this.hintText = hintText;
        //textArea.setText(hintText);  //默认直接显示
        //textArea.setForeground(Color.GRAY);
    }

    @Override
    public void focusGained(FocusEvent e) {
        //获取焦点时，清空提示内容
        String temp = textArea.getText();
        if(temp.equals(hintText)) {
            textArea.setText("");
            textArea.setForeground(Color.BLACK);
        }

    }

    @Override
    public void focusLost(FocusEvent e) {
        //失去焦点时，没有输入内容，显示提示内容
        String temp = textArea.getText();
        if(temp.equals("")) {
            textArea.setForeground(Color.GRAY);
            textArea.setText(hintText);
        }

    }

}
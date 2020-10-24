package burp;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import net.miginfocom.swing.MigLayout;
import org.apache.commons.text.StringEscapeUtils;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

class Token {
    public String name;
    public String regex;
    public String value;
    public Token(String name, String regex, String value){
        this.name = name;
        this.regex = regex;
        this.value = value;
    }

    @Override
    public String toString(){
        return String.format("%s: %s -> %s",name,regex,value);
    }
}

/* TODO: add functionality to have multiple regexes for one handling action
    maybe add a seperate identifier for the action handler name?
 */

enum tokenType {
    TOKEN, // handles regexing to obtain token
    REPLACE // handles regexing to replace with tokens
}

// Token Action Handler which regexes macro for values
class TokenHandler implements ISessionHandlingAction{
    public Token token;
    private tokenType type;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private DefaultListModel<Token> tokenList;
    public TokenHandler(Token token,IBurpExtenderCallbacks callbacks, tokenType type, DefaultListModel<Token> tokenList){
        super();
        this.token = token;
        this.type = type;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.tokenList = tokenList;
    }

    @Override
    public String getActionName() {
        return "SessionJar Action: "+token.name;
    }

    private String genReplace(String value){
        String repValue = value;
        for (int i = 0; i< tokenList.size(); i++){
            repValue = value.replace("{{"+ tokenList.get(i).name+"}}", tokenList.get(i).value);
        }
        return repValue;
    }

    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
        // action handler was not added as part of a macro
        if (macroItems == null && type==tokenType.REPLACE){
            // value regex pattern
            Pattern rPattern;
            Matcher rMatch = null;
            // regex capture string
            String capture = null;
            // compile regex string
            try{
                rPattern = Pattern.compile(token.regex);
            } catch (PatternSyntaxException e){
                callbacks.issueAlert("Syntax error in regex string, see extension error tab");
                callbacks.printError(e.toString());
                return;
            }

            // get response
            byte[] bReq = currentRequest.getRequest();
            if (bReq == null) return;

            // convert to string
            String sReq = helpers.bytesToString(bReq);

            // generate replacement string
            String replacement = StringEscapeUtils.unescapeJava(genReplace(this.token.value));

            // check for pattern in response
            rMatch = rPattern.matcher(sReq);
            if(rMatch.find()){
                // sReq = new StringBuilder(sReq).replace(rMatch.start(1), rMatch.end(1), replacement).toString();
                sReq = rMatch.replaceAll(replacement);
            }

            // set new request
            currentRequest.setRequest(sReq.getBytes());

        }else if(macroItems != null && type==tokenType.TOKEN) {
            // value regex pattern
            Pattern rPattern;
            Matcher rMatch = null;
            // regex capture string
            String capture = null;
            // compile regex string
            try {
                rPattern = Pattern.compile(token.regex);
            } catch (PatternSyntaxException e) {
                callbacks.issueAlert("Syntax error in regex string, see extension error tab");
                callbacks.printError(e.toString());
                return;
            }

            // iterate ever macro response in action (session handler rule)
            for (int x = 0; x < macroItems.length; x++) {
                // get response
                byte[] bResp = macroItems[x].getResponse();
                if (bResp == null) return;

                // convert to string
                String sResp = helpers.bytesToString(bResp);


                // check for pattern in response
                rMatch = rPattern.matcher(sResp);
                if (rMatch.find()) {
                    // capture groups start at 1
                    capture = rMatch.group(1);
                    if (capture != null && capture.length() > 0) {
                        // regex found
                        break;
                    }
                }
            }
            if (capture == null) {
                callbacks.printError("Regex/capture group not found in macro response");
                return;
            }
            token.value = capture;
        }
    }
}

public class BurpTab {
    private JPanel RootPanel;
    // tokens
    public DefaultListModel<Token> tokenList;
    private JList<Token> tokenListView;
    private JScrollPane tokenScroll;
    private JButton tokenUp;
    private JButton tokenDown;
    private JButton tokenAdd;
    private JButton tokenDel;
    private JTextField tokenNameField;
    private JTextField tokenRegexField;
    private JTextField tokenValueField;
    // replaces
    public DefaultListModel<Token> replaceList;
    private JList<Token> replaceListView;
    private JScrollPane replaceScroll;
    private JButton replaceUp;
    private JButton replaceDown;
    private JButton replaceAdd;
    private JButton replaceDel;
    private JTextField replaceNameField;
    private JTextField replaceRegexField;
    private JTextField replaceValueField;

    private IBurpExtenderCallbacks callbacks;

    public void saveSettings() {
        // convert list to json and save
        Gson gson = new Gson();
        Type listType = new TypeToken<DefaultListModel<Token>>(){}.getType();
        String json;

        json = gson.toJson(tokenList,listType);
        callbacks.saveExtensionSetting("tokenList",json);
        json = gson.toJson(replaceList,listType);
        callbacks.saveExtensionSetting("replaceList",json);
    }

    public void loadSettings() {
        // load settings
        Gson gson = new Gson();
        Type listType = new TypeToken<DefaultListModel<Token>>(){}.getType();
        String json;

        json = callbacks.loadExtensionSetting("tokenList");
        tokenList = gson.fromJson(json, listType);
        json = callbacks.loadExtensionSetting("replaceList");
        replaceList = gson.fromJson(json, listType);

        loadTokenActions(tokenList,tokenType.TOKEN);
        loadTokenActions(replaceList,tokenType.REPLACE);
    }
    // load actions for handlers
    public void loadTokenActions(DefaultListModel<Token> tList,tokenType type){
        if(tList == null)return;
        for(int i =0;i<tList.size();i++){
             callbacks.registerSessionHandlingAction(new TokenHandler(tList.elementAt(i),callbacks,type,tokenList));
        }
    }

    public Optional<Token> getByName(final DefaultListModel<Token> dList, final String name){
        List<Token> list = (List<Token>)(Object) Arrays.asList(dList.toArray());
        return list.stream().filter(o -> o.name.equals(name)).findFirst();
    }

    public void removeActionByToken(Token token){
        // shouldn't cast a interface to its implement
        List<TokenHandler> actions = (List<TokenHandler>)(Object) callbacks.getSessionHandlingActions();
        Optional op = actions.stream().filter(o -> o.token.equals(token)).findFirst();
        if (op.isPresent()){
            callbacks.removeSessionHandlingAction((ISessionHandlingAction) op.get());
        }
    }

    public BurpTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        loadSettings();
        // if there is no previous data
        if (tokenList == null) tokenList = new DefaultListModel<>();
        if (replaceList == null) replaceList = new DefaultListModel<>();
        setupUI();

        // token add button
        tokenAdd.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Optional<Token> op = getByName(tokenList,tokenNameField.getText());
                Token token;
                if(op.isPresent()) {
                    token = op.get();
                    token.name = tokenNameField.getText();
                    token.regex = tokenRegexField.getText();
                    token.value = tokenValueField.getText();

                    // repaint lists
                    tokenListView.repaint();
                    tokenScroll.repaint();
                }else {
                    token = new Token(tokenNameField.getText(), tokenRegexField.getText(), tokenValueField.getText());
                    tokenList.addElement(token);
                    // add action to handlers
                    callbacks.registerSessionHandlingAction(new TokenHandler(token,callbacks,tokenType.TOKEN,tokenList));
                }
                saveSettings();
            }
        });
        // token del button
        tokenDel.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Token selected = tokenListView.getSelectedValue();
                tokenList.removeElement(selected);
                removeActionByToken(selected);

                saveSettings();
            }
        });
        tokenUp.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Token selected;
                Token temp;
                int index;

                // get element of selected and index
                selected = tokenListView.getSelectedValue();
                if (selected == null)return;
                index = tokenList.indexOf(selected);

                try {
                    // swap elements
                    temp = tokenList.set(index-1,selected);
                    tokenList.set(index,temp);
                    tokenListView.setSelectedIndex(index-1);
                }catch(ArrayIndexOutOfBoundsException exp){
                    // out of bounds
                    return;
                }
            }
        });
        tokenDown.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Token selected;
                Token temp;
                int index;

                // get element of selected and index
                selected = tokenListView.getSelectedValue();
                if (selected == null)return;
                index = tokenList.indexOf(selected);

                try {
                    // swap elements
                    temp = tokenList.set(index+1,selected);
                    tokenList.set(index,temp);
                    tokenListView.setSelectedIndex(index+1);
                }catch(ArrayIndexOutOfBoundsException exp){
                    // out of bounds
                    return;
                }
            }
        });
        // token list selection
        tokenListView.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                Token selected = tokenListView.getSelectedValue();
                if (selected == null)return;
                tokenNameField.setText(selected.name);
                tokenRegexField.setText(selected.regex);
                tokenValueField.setText(selected.value);
            }
        });

        // replace add button
        replaceAdd.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Optional<Token> op = getByName(replaceList,replaceNameField.getText());
                Token replace;
                if(op.isPresent()) {
                    replace = op.get();
                    replace.name = replaceNameField.getText();
                    replace.regex = replaceRegexField.getText();
                    replace.value = replaceValueField.getText();

                    // repaint lists
                    replaceListView.repaint();
                    replaceScroll.repaint();
                }else {
                    replace = new Token(replaceNameField.getText(), replaceRegexField.getText(), replaceValueField.getText());
                    replaceList.addElement(replace);
                    // add action to handlers
                    callbacks.registerSessionHandlingAction(new TokenHandler(replace,callbacks,tokenType.REPLACE,tokenList));
                }
                saveSettings();
            }
        });
        // replace del button
        replaceDel.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Token selected = replaceListView.getSelectedValue();
                replaceList.removeElement(selected);
                removeActionByToken(selected);

                saveSettings();
            }
        });
        replaceUp.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Token selected;
                Token temp;
                int index;

                // get element of selected and index
                selected = replaceListView.getSelectedValue();
                if (selected == null)return;
                index = replaceList.indexOf(selected);

                try {
                    // swap elements
                    temp = replaceList.set(index-1,selected);
                    replaceList.set(index,temp);
                    replaceListView.setSelectedIndex(index-1);
                }catch(ArrayIndexOutOfBoundsException exp){
                    // out of bounds
                    return;
                }
            }
        });
        replaceDown.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Token selected;
                Token temp;
                int index;

                // get element of selected and index
                selected = replaceListView.getSelectedValue();
                if (selected == null)return;
                index = replaceList.indexOf(selected);

                try {
                    // swap elements
                    temp = replaceList.set(index+1,selected);
                    replaceList.set(index,temp);
                    replaceListView.setSelectedIndex(index+1);
                }catch(ArrayIndexOutOfBoundsException exp){
                    // out of bounds
                    return;
                }
            }
        });

        // replace list selection
        replaceListView.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                Token selected = replaceListView.getSelectedValue();
                if (selected == null)return;
                replaceNameField.setText(selected.name);
                replaceRegexField.setText(selected.regex);
                replaceValueField.setText(selected.value);
            }
        });
    }

    private void setupUI() {
        RootPanel = new JPanel(new MigLayout());

        // token list
        tokenListView = new JList(tokenList);
        tokenListView.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tokenListView.setLayoutOrientation(JList.VERTICAL);
        RootPanel.add(new JLabel("<html><b>Tokens:</b><html>"),"span 6, wrap");
        tokenScroll = new JScrollPane(tokenListView);
        RootPanel.add(tokenScroll,"span 6 2, grow");
        tokenUp = new JButton("▲");
        RootPanel.add(tokenUp, "wrap");
        tokenDown = new JButton("▼");
        RootPanel.add(tokenDown, "wrap");

        // token edit panel
        tokenAdd = new JButton("Add");
        RootPanel.add(tokenAdd);
        tokenDel = new JButton("Del");
        RootPanel.add(tokenDel);
        tokenNameField = new JTextField("Name");
        tokenNameField.setMinimumSize(new Dimension(50,-1));
        RootPanel.add(tokenNameField);
        tokenRegexField = new JTextField("Regex");
        RootPanel.add(tokenRegexField, "width 125:200:500, grow");
        tokenValueField = new JTextField("Value");
        RootPanel.add(tokenValueField, "width 125:200:500, wrap, grow");

        // replace list
        replaceListView = new JList(replaceList);
        replaceListView.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        replaceListView.setLayoutOrientation(JList.VERTICAL);
        RootPanel.add(new JLabel("<html><b>Replaces:</b><html>"),"span 6, wrap");
        replaceScroll = new JScrollPane(replaceListView);
        RootPanel.add(replaceScroll,"span 6 2,grow");
        replaceUp = new JButton("▲");
        RootPanel.add(replaceUp, "wrap");
        replaceDown = new JButton("▼");
        RootPanel.add(replaceDown, "wrap");

        // replace edit panel
        replaceAdd = new JButton("Add");
        RootPanel.add(replaceAdd);
        replaceDel = new JButton("Del");
        RootPanel.add(replaceDel);
        replaceNameField = new JTextField("Name");
        replaceNameField.setMinimumSize(new Dimension(50,-1));
        RootPanel.add(replaceNameField);
        replaceRegexField = new JTextField("Regex");
        RootPanel.add(replaceRegexField, "width 125:200:500, grow");
        replaceValueField = new JTextField("Fill");
        RootPanel.add(replaceValueField, "width 125:200:500, grow, wrap");

        RootPanel.add(new JLabel("<html><h1>Usage:</h1><p>Tokens, and Regex Replaces are added as <b>Extension action handlers</b> by name</p><h2>Tokens:</h2><p>To update a tokens value with a regex add a <b>Session Handling Rule</b> <u>(Project options/Sessions/Session Handling Rules)</u> and choose your token name as a <b>action handler</b> at the end of a macro/check session. The Token rule will parse the previous macro requests to find the regex and update the token</p><p><b>Validate session only every x request</b> is recommened to be used as to not overload your scanning</p><p><b>Scope</b> is also recommened to be set</p><h2>Replaces:</h2><p>To replace tokens in requests burp makes, add a <b>Session Handling Rule</b> <u>(Project options/Sessions/Session Handling Rules)</u> and choose your replace name as an <b>Invoked extension handler</b></p></html>\n"),"span 6");

        RootPanel.setVisible(true);
    }

    public JComponent getRootComponent() {
        return RootPanel;
    }

}

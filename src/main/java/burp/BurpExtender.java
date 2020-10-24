package burp;
import java.awt.*;

// intellij forms: https://www.secpulse.com/archives/124593.html
public class BurpExtender implements IBurpExtender,ITab{
    IBurpExtenderCallbacks callbacks = null;
    private IExtensionHelpers helpers;
    private BurpTab tab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        callbacks.setExtensionName ("Session Jar V2");

        // add new JPanel tab
        tab = new BurpTab(callbacks);
        callbacks.addSuiteTab(this);

        callbacks.printOutput("Session Jar V2 loaded");
    }

    @Override
    public String getTabCaption() {
        return "Session Jar";
    }

    @Override
    public Component getUiComponent() {
        return tab.getRootComponent();
    }

}

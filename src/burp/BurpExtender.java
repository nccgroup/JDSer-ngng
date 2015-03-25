package burp;


import javax.swing.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory {


    private static final String LIB_DIR = "./libs/";
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // obtain an extension helpers object
        helpers = callbacks.getHelpers();

        // set our extension name
        callbacks.setExtensionName("BurpJDSer-ngng, extended by Jon Murray 03/2015");

        JDTabFactory tab = new JDTabFactory(this.callbacks, this.helpers);

        // register ourselves as a message editor tab factory
        callbacks.registerMessageEditorTabFactory(tab);

        callbacks.registerContextMenuFactory(new JDMenu(this.callbacks, this.helpers));

        callbacks.registerHttpListener(new JDHttpListener(this.helpers));

        JDUtils.refreshSharedClassLoader();
    }

    //
    // implement IMessageEditorTabFactory
    //
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable)
    {
        // create a new instance of our custom editor tab
        return new JDTab(controller, editable, this.callbacks, this.helpers);
    }

    //
    // implement IContextMenuFactory
    //
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menu = new ArrayList<>();
        Action reloadJarsAction = new ReloadJarsAction("BurpJDSer-ng: Reload JARs", invocation);
        JMenuItem reloadJars = new JMenuItem(reloadJarsAction);
        
        menu.add(reloadJars);
        return menu;
    }
    
    class ReloadJarsAction extends AbstractAction {

        IContextMenuInvocation invocation;
        
        public ReloadJarsAction(String text, IContextMenuInvocation invocation) {
            super(text);
            this.invocation = invocation;
        }
        
        @Override
        public void actionPerformed(ActionEvent e) {
           System.out.println("Reloading jars from " + LIB_DIR);
           JDUtils.refreshSharedClassLoader();
        }
        
    }
}